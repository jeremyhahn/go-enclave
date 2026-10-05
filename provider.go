// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "context"

// This file is the sealing seam: the two interfaces a crypto provider
// implements so that sealing can be rooted in hardware WITHOUT this package
// importing any. go-enclave ships exactly one implementation — the pure
// software [SoftwareProvider] — and defines the contract everything else is
// injected against. A TPM, HSM or cloud-KMS provider is built in a higher
// layer and passed down through [NewSealer] or [SetSealer]; no hardware code
// may ever land here, because this package sits at the bottom of the build
// graph of everything that handles key material.
//
// There are TWO interfaces rather than the one the architecture sketch drew,
// and the reason is where a mismatch is caught. A provider implements only
// what its mode needs — an HSM built for per-operation work has no root to
// unseal, and a TPM used only to gate a root key need not expose per-value
// protection. With the capabilities split, [NewSealer] checks the provider
// against the selected [Mode] at CONSTRUCTION and refuses a mismatch with
// [ErrProviderMode] — a misconfiguration that fails at boot, instead of at the
// first credential read hours later under a mode the provider silently could
// not serve.

// RootKeyBytes is the size of the buffer [RootUnsealer.UnsealRoot] receives,
// and therefore the size of every root key in this package: 32 bytes, an
// AES-256 key.
//
// It is a constant of the seam rather than a per-provider choice so that a
// provider knows exactly what to produce without a negotiation step, and so
// the destination can be allocated in locked memory before the provider is
// ever called.
const RootKeyBytes = 32

// KeyProtector protects short key material outside this process. It is the
// provider seam for [ModePerOperation]: every seal and open calls the device,
// on the per-value data key only — never on the material itself, which would
// send the plaintext across a device boundary and bring it back into ordinary
// heap memory (see [Mode]).
//
// # Implementations MUST be authenticated
//
// Unprotect returns an error for any blob this provider's Protect did not
// produce — bit-flipped, truncated, forged, or made by a different provider.
// A provider offering confidentiality alone does NOT satisfy this interface.
// The disqualifying example is bare RSA-OAEP: it wraps under a PUBLIC key, so
// anyone holding that key can wrap a key of their choosing and forge a sealed
// value that opens successfully to attacker-chosen material. That gap is why
// this contract exists; a provider holding only a decryption key must be
// COMPOSED with a signing key to qualify — go-enclave does not ship such a
// composition, and that is settled rather than pending (issue #50). The
// reason is SCOPE, not memory: this package defines the seam and ships the
// software default, and device-backed providers are built and injected by the
// layer that owns those devices. A generic crypto.Decrypter bridge here would
// put the bottom of the dependency graph in the business of adapting backends
// it cannot exercise; the same bridge, written where those backends live, can
// be held to the conformance suite in providertest. No capability is lost by
// that: every realistic authenticated backend has a native operation below
// crypto.Decrypter and qualifies on its own — cloud-KMS Encrypt/Decrypt is
// authenticated, an HSM can AES-GCM under a device key, and TPM 2.0
// seal/unseal is integrity-protected. The composition is the provider
// author's to build.
//
// A blob that fails authentication is reported with an error matching
// [ErrSealedAuthentication], so a forgery reads as what it is at every layer
// above. Any OTHER failure — a device unreachable, a session limit, a
// context that ended — is reported as the provider's own error and surfaces
// from [SealedEnclave.Open] joined under [ErrOpenFailed], never under
// ErrSealedAuthentication, with the provider's error still reachable through
// errors.Is and errors.As: an infrastructure fault dressed as an
// authentication failure sends an operator hunting an attacker who does not
// exist.
//
// # The contract, operation by operation
//
// Protect encrypts-and-authenticates key (always [RootKeyBytes] long in this
// package's use) and returns a non-empty blob. The blob is OPAQUE to
// go-enclave: key identifiers, algorithm markers and versioning all live
// inside it, which is what lets a provider evolve its format without an
// upstream change here. Protect must not retain key or any copy of it; the
// slice aliases locked pages that are wiped and unmapped when the caller is
// done. The [Sealer] copies the returned blob before using it, so the
// provider keeps ownership of that slice and may reuse it once Protect has
// returned; the Sealer never writes to it.
//
// Unprotect must not retain or modify blob: it is the Sealer's copy, wiped
// when the sealed value is destroyed.
//
// Unprotect recovers the protected key INTO key, a caller-supplied buffer of
// exactly the length Protect received — a length mismatch is an
// authentication failure, not a truncation. The destination is caller-supplied
// so that a provider whose library can decrypt in place writes the key
// straight into locked memory and it never exists anywhere else. A provider
// whose underlying API returns a fresh slice (crypto.Decrypter does) must
// copy into key and wipe its transient, accepting the in-call heap window
// that interface shape imposes.
//
// # Both operations take a context, and MUST honor it
//
// The provider context contract is stated once, on [RootUnsealer], and
// applies to Protect and Unprotect exactly as it does to UnsealRoot.
type KeyProtector interface {
	Protect(ctx context.Context, key []byte) (blob []byte, err error)
	Unprotect(ctx context.Context, blob []byte, key []byte) error
}

// RootUnsealer yields the process root key for [ModeRootKey]: the device is
// consulted once, the root lands in locked memory, and every subsequent
// operation is in-process software crypto keyed under it (see [Mode] for what
// that trades away).
//
// UnsealRoot writes the root key into dst, which is always exactly
// [RootKeyBytes] long and aliases locked pages the caller prepared — the same
// recover-into-caller-memory shape as [KeyProtector.Unprotect], for the same
// reason. A provider that cannot produce the root — device absent, PCR policy
// unsatisfied, quota exceeded — returns its own error, and the first seal
// fails with it rather than falling back to anything.
//
// A [Sealer] calls UnsealRoot at most once, retrying only if that call
// failed. The value returned on that one call is the root for the Sealer's
// whole lifetime, so a provider gating the root on device state (a TPM PCR
// policy, say) is enforcing that state at unseal time, not continuously. A
// call refused because its context ended is a FAILED call: the Sealer will
// ask again, so a provider holding a one-shot handle must not consume it on a
// call it did not complete.
//
// # The provider context contract (all three operations)
//
// Every provider operation can block — on a device round trip, a session
// limit, a network hop to a KMS — so every one takes the caller's context, and
// a provider MUST honor it:
//
//   - a context that has already ended at entry is refused before any device
//     work, with an error matching ctx.Err() under [errors.Is];
//   - a context that ends DURING the operation makes it return promptly, with
//     an error matching ctx.Err(), as far as the underlying API allows — a
//     device library that takes no context is the provider author's to bound;
//   - a refused call writes no key material into the destination and, for
//     UnsealRoot, consumes nothing a later call needs.
//
// The reason this is a MUST and not a courtesy is where the bound lives. A
// caller's deadline is real only if every layer between it and the blocking
// operation honors it; [Sealer.Seal] and [SealedEnclave.Open] check the
// context before and after every provider call and hold no mutex across one —
// the one lock that does span a provider call is the init semaphore
// serializing a Sealer's FIRST root unseal, and a caller queued on it leaves
// when its own context ends. They cannot interrupt a provider that ignores
// its context: that caller waits as long as the provider does. What the Sealer
// does guarantee is that such a provider stalls ONLY its own caller: no other
// Seal or Open, on this Sealer or any other, waits behind it beyond its own
// context (#87). The conformance suite in providertest checks the refusal
// half of this contract.
//
// A canceled or expired call surfaces from Seal under [ErrSealFailed] and
// from Open under [ErrOpenFailed], in both cases matching the context's error
// as well. It does not match [ErrSealedAuthentication] unless the provider
// itself reported an authentication failure before the context was seen to
// end: that is a verdict on the blob — a security signal — and is kept
// visible alongside the cancellation rather than overwritten by it.
type RootUnsealer interface {
	UnsealRoot(ctx context.Context, dst []byte) error
}

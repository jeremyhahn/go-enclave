// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "context"

// RootKeyBytes is the length of every root key and of every key handed to a
// provider: 32 bytes, an AES-256 key. It is fixed so the destination can be
// allocated in locked memory before the provider is called.
const RootKeyBytes = 32

// KeyProtector protects short key material outside this process. It is the
// provider seam for [ModePerOperation], selected with [WithKeyProtector]:
// every seal and open calls it on the per-value data key, never on the
// material itself.
//
// Implementations must be authenticated. Unprotect returns an error matching
// [ErrSealedAuthentication] for any blob this provider's Protect did not
// produce: tampered, truncated, forged, or made by a different provider. A
// confidentiality-only scheme such as bare RSA-OAEP, which anyone holding the
// public key can use to wrap a key of their choosing, does not qualify. Any
// other failure (device unreachable, session limit, ended context) is
// returned as the provider's own error, never as ErrSealedAuthentication;
// [SealedEnclave.Open] joins it under [ErrOpenFailed] with the provider's
// error still reachable through errors.Is and errors.As.
//
// Protect encrypts and authenticates key (always [RootKeyBytes] long) and
// returns a non-empty blob that is opaque to this package; key identifiers
// and versions belong inside it. Protect must not retain key or any copy of
// it: key aliases locked pages that are wiped and unmapped afterwards. The
// [Sealer] copies the returned blob and never writes to it, so the provider
// keeps ownership of that slice and may reuse it once Protect returns.
//
// Unprotect recovers the key into key, a caller-supplied buffer of exactly
// the length Protect received, aliasing locked pages. A length mismatch is an
// authentication failure. Unprotect must not retain or modify blob. A
// provider whose underlying API returns a fresh slice must copy it into key
// and wipe the transient.
//
// Both operations must honor ctx as described on [RootUnsealer]. A [Sealer]
// holds no lock across a provider call, so concurrent seals and opens call
// the provider concurrently.
type KeyProtector interface {
	Protect(ctx context.Context, key []byte) (blob []byte, err error)
	Unprotect(ctx context.Context, blob []byte, key []byte) error
}

// RootUnsealer yields the process root key for [ModeRootKey], selected with
// [WithRootUnsealer]: the provider is consulted once, the root lands in
// locked memory, and later operations are in-process software crypto under
// keys derived from it (see [Mode]).
//
// UnsealRoot writes the root into dst, which is exactly [RootKeyBytes] long
// and aliases locked pages. A provider that cannot produce the root (device
// absent, policy unsatisfied, quota exceeded) returns its own error, and the
// seal fails with it.
//
// A [Sealer] calls UnsealRoot until one call succeeds, and never again; the
// root from that call serves the Sealer's whole lifetime, so a provider
// gating the root on device state enforces it at unseal time only. A call
// refused because its context ended is a failed call and will be retried, so
// it must not consume a one-shot resource.
//
// Context contract, for UnsealRoot, Protect and Unprotect alike:
//
//   - a context already ended at entry is refused before any device work,
//     with an error matching ctx.Err() under [errors.Is];
//   - a context that ends during the operation makes it return promptly, with
//     an error matching ctx.Err(), as far as the underlying API allows;
//   - a refused call writes no key material into the destination and, for
//     UnsealRoot, consumes nothing a later call needs.
//
// The Sealer holds no mutex of its own across a provider call (only the
// one-slot init semaphore spans the first UnsealRoot, and waiters leave when
// their context ends), so a provider that ignores its context stalls only its
// own caller. A canceled call surfaces from Seal under [ErrSealFailed] and
// from Open under [ErrOpenFailed], also matching the context's error; an
// authentication verdict the provider returned stays visible alongside it.
// The conformance suite in package providertest checks the refusal half.
type RootUnsealer interface {
	UnsealRoot(ctx context.Context, dst []byte) error
}

// HealthReporter is an optional capability of a [KeyProtector], found by type
// assertion and consulted by [SealedEnclave.Openable].
//
// Health returns nil if the provider can still unprotect what it protected,
// and an error matching [ErrSealerWiped] (or [ErrSealerDestroyed]) if a
// shutdown [WipeAll] or Destroy took in-process key material it depends on.
// It is not a device liveness probe: a provider whose key lives in a TPM, HSM
// or KMS should return nil unconditionally. Health must not block; it takes
// no context and is called with no lock of this package's held.
//
// The answer is believed. A KeyProtector without HealthReporter gets
// [ErrOpenabilityUnknown] after a sweep. In [ModeRootKey] the sealer inspects
// its own hierarchy, and a [RootUnsealer]'s HealthReporter is not consulted.
type HealthReporter interface {
	Health() error
}

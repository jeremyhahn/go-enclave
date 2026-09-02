// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"errors"
	"sync"
)

// ErrProviderMessageLimit reports that a [SoftwareProvider] has performed as
// many Protect operations as its single root key may safely encrypt, and is
// refusing further ones.
//
// It exists because the software provider deliberately has NO rotation
// machinery: in [ModeRootKey] — its intended mode, and the process default —
// Protect is never called at all (the Sealer's KEK hierarchy owns rotation,
// and the root wraps one blob per KEK generation), so rotation here would be
// dead weight guarding a bound that cannot be approached. In
// [ModePerOperation] each seal costs a Protect, so a process that runs the
// software provider per-operation at extreme volume CAN approach the AES-GCM
// per-key message bound, and the safe answer is a typed refusal rather than a
// silent nonce-collision risk. A caller that hits this is holding the
// pure-software provider in the mode built for hardware; the fix is
// [ModeRootKey], which rotates, or a hardware [KeyProtector], which owns its
// own bounds.
var ErrProviderMessageLimit = errors.New("enclave: software provider reached its per-key message bound; use ModeRootKey or a hardware provider")

// softwareProtectLimit is the Protect budget of the software provider's one
// root key: half of crypto/cipher's documented 2^32-message ceiling for a key
// under NewGCMWithRandomNonce, the same margin [kekMessageLimit] takes and
// for the same reason — the birthday bound on the random nonce is all that
// prevents a repeat, and a repeated GCM nonce is a break.
const softwareProtectLimit = 1 << 31

// SoftwareProvider is the pure-software crypto provider, and the only one
// go-enclave ships. It satisfies BOTH seam interfaces so that either [Mode]
// works with no hardware and no configuration:
//
//   - [RootUnsealer]: UnsealRoot yields a root key generated into a
//     [MemoryEnclave] at first use. This makes [ModeRootKey] the
//     out-of-the-box behavior — plain software sealing, hardware nowhere.
//   - [KeyProtector]: Protect/Unprotect are AES-GCM under that same root,
//     which makes [ModePerOperation] exercisable without a device. That is
//     for tests and development shape-parity, not a security posture: with a
//     software provider the "device" is this process, so per-operation mode
//     buys none of the boundedness it exists for.
//
// # The honest limitation, in the same breath as the capability
//
// The root is generated in this process and lives in a locked, undumpable
// enclave here — so unlike a hardware provider, an adversary who can read
// this process's live memory (or swap, for the heap transits documented on
// [withAEAD]) obtains the key that opens everything. What sealing under this
// provider DOES buy: the material is unreadable in a core dump or a swap
// artifact between opens, and a shutdown [WipeAll] destroys the root and with
// it every sealed value at once. Callers whose threat model includes a
// live-memory adversary need a hardware provider; that is the entire reason
// the seam exists.
//
// After a shutdown sweep destroys the root, every method fails closed with
// [ErrSealerWiped] — never a silent fresh root; see that error for why.
//
// The zero value is NOT usable; construct with [NewSoftwareProvider]. A
// SoftwareProvider is safe for concurrent use.
type SoftwareProvider struct {
	mu sync.Mutex
	// root is created on first use and retried on failure rather than
	// memoized: the first attempt can fail at the RLIMIT_MEMLOCK ceiling, and
	// a ceiling is a condition that lifts. Non-nil-but-dead means a shutdown
	// sweep destroyed it, which is the one state that must NOT regenerate.
	root *MemoryEnclave
	// protects counts Protect operations charged to the root, incremented
	// before each attempt so a failed one still consumes budget —
	// over-counting refuses slightly early, the safe direction to be wrong
	// in. UnsealRoot and Unprotect are not counted: the bound is on
	// encryptions.
	protects uint64
}

// NewSoftwareProvider returns a software provider with no root yet; the root
// is generated at first use so that merely constructing one — which
// [NewSealer] does by default — costs no locked memory.
func NewSoftwareProvider() *SoftwareProvider {
	return &SoftwareProvider{}
}

// rootLocked returns the root enclave, generating it on first use. The
// caller holds p.mu.
func (p *SoftwareProvider) rootLocked() (*MemoryEnclave, error) {
	if p.root != nil {
		if !p.root.IsAlive() {
			return nil, ErrSealerWiped
		}
		return p.root, nil
	}
	root, err := newKeyEnclave(RootKeyBytes)
	if err != nil {
		return nil, err
	}
	p.root = root
	return root, nil
}

// swept translates an [ErrEnclaveDestroyed] surfacing from a use of the root
// enclave. Only [WipeAll] can destroy it — this provider never does — so the
// honest report is [ErrSealerWiped], for the same misattribution reason
// documented on that error.
func swept(err error) error {
	if errors.Is(err, ErrEnclaveDestroyed) {
		return ErrSealerWiped
	}
	return err
}

// Protect implements [KeyProtector]: key is wrapped with AES-GCM under the
// provider root, with the blob's frame bound as AAD.
//
// It returns [ErrProviderMessageLimit] once the root's encryption budget is
// spent, [ErrSealerWiped] after a shutdown sweep, and
// [ErrLockedMemoryUnavailable] if the root cannot be created on first use.
func (p *SoftwareProvider) Protect(key []byte) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	root, err := p.rootLocked()
	if err != nil {
		return nil, err
	}
	if p.protects >= softwareProtectLimit {
		return nil, ErrProviderMessageLimit
	}
	p.protects++

	// The generation field of the frame is zero: this provider has exactly
	// one root for its lifetime, which is what the message bound above is
	// protecting.
	header := blobHeader(blobKindProvider, 0)
	body, err := sealWithKey(root, key, header)
	if err != nil {
		return nil, swept(err)
	}
	return append(header, body...), nil
}

// Unprotect implements [KeyProtector]: it recovers a Protect-produced blob
// into key, refusing — with [ErrSealedAuthentication], per the contract —
// anything its own Protect did not produce: tampered, truncated, misframed,
// or wrapped by a different provider instance.
func (p *SoftwareProvider) Unprotect(blob, key []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.root == nil {
		// This provider has protected nothing, so no blob can be its own.
		return ErrSealedAuthentication
	}
	if !p.root.IsAlive() {
		return ErrSealerWiped
	}

	kind, gen, body, err := parseBlobHeader(blob)
	if err != nil || kind != blobKindProvider || gen != 0 {
		return ErrSealedAuthentication
	}

	return swept(openWithKeyInto(p.root, body, blob[:blobHeaderLen], key))
}

// UnsealRoot implements [RootUnsealer]: it copies the provider root —
// generated at first use — into dst, which must be exactly [RootKeyBytes]
// long; any other length is [ErrInvalidSize], a programming mistake rather
// than a runtime condition.
//
// The copy means the root then exists in TWO locked enclaves: the provider's
// and the Sealer's. That is the seam working as designed — the Sealer treats
// every provider identically and owns the copy it uses — and both copies are
// registered, so a shutdown sweep destroys both and the fail-closed contract
// holds from either side.
func (p *SoftwareProvider) UnsealRoot(dst []byte) error {
	if len(dst) != RootKeyBytes {
		return ErrInvalidSize
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	root, err := p.rootLocked()
	if err != nil {
		return err
	}
	return swept(root.WithBytes(func(b []byte) error {
		copyConstantTime(dst, b)
		return nil
	}))
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"context"
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
// this process's live memory obtains the key that opens everything. Nor are
// swap and core dumps fully closed: each seal and open leaves AES key
// schedules on the ordinary heap — the value's DEK, and the KEK (in
// [ModeRootKey]) or this root (in [ModePerOperation]) that wraps it — unwiped
// unless the build erases them (see [KeyScheduleErasure] and [withAEAD]).
// What sealing under this provider DOES buy: plaintext is never on the heap,
// the root itself is never in a dump or swap, and [SoftwareProvider.Destroy]
// or a shutdown [WipeAll] destroys the root and with it every sealed value at
// once. Callers whose threat model includes a live-memory adversary need a
// hardware provider; that is the entire reason the seam exists.
//
// After a shutdown sweep destroys the root, every method fails closed with
// [ErrSealerWiped], and after [SoftwareProvider.Destroy] with
// [ErrSealerDestroyed] — never a silent fresh root; see [ErrSealerWiped] for
// why.
//
// Every method honors its context the way the seam requires (see
// [RootUnsealer]): one that has ended at entry is refused with ctx.Err()
// before the root is touched — and before one is generated, so a canceled
// first call costs no locked memory. Nothing in this provider blocks beyond
// its own short critical section, so there is no mid-call cancellation to
// observe; the entry check is the whole of what honoring it means here.
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
	// destroyed is set by Destroy and never cleared.
	destroyed bool
}

// SoftwareProvider is the default provider for both modes — [NewSealer] uses it
// as a [KeyProtector] under [ModePerOperation] and as a [RootUnsealer] under
// [ModeRootKey]. The provider reaches the Sealer untyped and is matched against
// the seam at run time, so without these a signature drift on either interface
// would still compile and surface only as [ErrProviderMode] from the DEFAULT
// constructor. They make it fail the build here instead.
var (
	_ KeyProtector = (*SoftwareProvider)(nil)
	_ RootUnsealer = (*SoftwareProvider)(nil)
)

// NewSoftwareProvider returns a software provider with no root yet; the root
// is generated at first use so that merely constructing one — which
// [NewSealer] does by default — costs no locked memory.
func NewSoftwareProvider() *SoftwareProvider {
	return &SoftwareProvider{}
}

// rootLocked returns the root enclave, generating it on first use. The
// caller holds p.mu.
func (p *SoftwareProvider) rootLocked() (*MemoryEnclave, error) {
	if p.destroyed {
		return nil, ErrSealerDestroyed
	}
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

// openable implements sealHealth: it reports [ErrSealerDestroyed] after
// Destroy, [ErrSealerWiped] once a shutdown sweep has destroyed this
// provider's root, and nil otherwise.
//
// It uses rootLocked's dead-root predicate but NOT rootLocked itself, because
// asking whether a value can be opened must not generate a root that did not
// exist — that would turn a diagnostic into an allocation of locked memory
// and a call to the CSPRNG. A nil root therefore reports nil: nothing was
// sealed through this provider, so nothing it holds is unopenable.
func (p *SoftwareProvider) openable() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.destroyed {
		return ErrSealerDestroyed
	}
	if p.root != nil && !p.root.IsAlive() {
		return ErrSealerWiped
	}
	return nil
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
// It returns ctx.Err() if ctx has already ended, [ErrProviderMessageLimit]
// once the root's encryption budget is spent, [ErrSealerWiped] after a
// shutdown sweep, and [ErrLockedMemoryUnavailable] if the root cannot be
// created on first use. A refused call charges nothing to the budget.
func (p *SoftwareProvider) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

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
// or wrapped by a different provider instance. A context that has already
// ended is refused with ctx.Err() before the blob is examined, so a canceled
// call writes nothing into key.
func (p *SoftwareProvider) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.destroyed {
		return ErrSealerDestroyed
	}
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
// than a runtime condition. A context that has already ended is refused with
// ctx.Err() before the root is generated or copied.
//
// The copy means the root then exists in TWO locked enclaves: the provider's
// and the Sealer's. That is the seam working as designed — the Sealer treats
// every provider identically and owns the copy it uses — and both copies are
// registered, so a shutdown sweep destroys both and the fail-closed contract
// holds from either side.
func (p *SoftwareProvider) UnsealRoot(ctx context.Context, dst []byte) error {
	if len(dst) != RootKeyBytes {
		return ErrInvalidSize
	}
	if err := ctx.Err(); err != nil {
		return err
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

// Destroy releases the provider's root. Every later call fails closed with
// [ErrSealerDestroyed], so everything it protected — and every [Sealer] that
// uses it — is unrecoverable. It waits for an operation in progress, which is
// in-process and short. A release the kernel refuses is reported and stays
// on the [WipeAll] ledger; calling Destroy again retries it. Destroy is
// idempotent and safe on a nil provider.
func (p *SoftwareProvider) Destroy() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.destroyed = true
	return p.root.Destroy()
}

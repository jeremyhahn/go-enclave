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

// softwareProtectLimit is half of crypto/cipher's 2^32-message bound for one
// key under NewGCMWithRandomNonce, the same margin as kekMessageLimit.
const softwareProtectLimit = 1 << 31

// SoftwareProvider is the pure-software provider, and the only one go-enclave
// ships. It implements [RootUnsealer] (the default for [ModeRootKey]),
// [KeyProtector] (AES-GCM under the same root, for tests and development of
// [ModePerOperation]) and [HealthReporter]. Its root is generated into a
// locked [MemoryEnclave] at first use.
//
// Because the root lives in this process, a reader of this process's live
// memory can recover it, and AES key schedules reach the heap as described on
// [Mode] and [KeyScheduleErasure]. Plaintext never reaches the heap, and the
// root is never in a dump or swap.
//
// After a shutdown sweep destroys the root every method fails with
// [ErrSealerWiped], and after [SoftwareProvider.Destroy] with
// [ErrSealerDestroyed]; it never generates a fresh root. Every method refuses
// a context already ended with ctx.Err() before the root is touched or
// generated; no method blocks beyond a short critical section.
//
// The zero value is not usable; construct with [NewSoftwareProvider]. A
// SoftwareProvider is safe for concurrent use.
type SoftwareProvider struct {
	mu sync.Mutex
	// root is created on first use and retried on failure, since a
	// RLIMIT_MEMLOCK refusal can lift. Non-nil but dead means a sweep
	// destroyed it, and it must not be regenerated.
	root *MemoryEnclave
	// protects counts Protect attempts, charged before each so a failed one
	// still counts; only encryptions count against the bound.
	protects uint64
	// destroyed is set by Destroy and never cleared.
	destroyed bool
}

// SoftwareProvider serves both modes and reports its own sweep state.
var (
	_ KeyProtector   = (*SoftwareProvider)(nil)
	_ RootUnsealer   = (*SoftwareProvider)(nil)
	_ HealthReporter = (*SoftwareProvider)(nil)
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
	root, err := p.liveRootLocked()
	if err != nil || root != nil {
		return root, err
	}
	if root, err = newKeyEnclave(RootKeyBytes); err != nil {
		return nil, err
	}
	p.root = root
	return root, nil
}

// liveRootLocked is the one statement of the provider's state: it reports
// [ErrSealerDestroyed] after Destroy, [ErrSealerWiped] once a shutdown sweep
// has destroyed the root, and otherwise the root, nil before first use. The
// caller holds p.mu.
func (p *SoftwareProvider) liveRootLocked() (*MemoryEnclave, error) {
	switch {
	case p.destroyed:
		return nil, ErrSealerDestroyed
	case p.root != nil && !p.root.IsAlive():
		return nil, ErrSealerWiped
	default:
		return p.root, nil
	}
}

// Health implements [HealthReporter]: it reports [ErrSealerDestroyed] after
// Destroy, [ErrSealerWiped] once a shutdown sweep has destroyed this
// provider's root, and nil otherwise, including when no root exists yet. It
// never generates a root.
func (p *SoftwareProvider) Health() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.liveRootLocked()
	return err
}

// swept translates [ErrEnclaveDestroyed] from a use of the root into
// [ErrSealerWiped]: only [WipeAll] can destroy the root.
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

	// The frame's generation field is zero: this provider has one root.
	blob, err := wrapKey(root, key, blobKindProvider, 0)
	if err != nil {
		return nil, swept(err)
	}
	return blob, nil
}

// Unprotect implements [KeyProtector]: it recovers a Protect-produced blob
// into key, refusing with [ErrSealedAuthentication] anything its own Protect
// did not produce: tampered, truncated, misframed, or wrapped by a different
// provider instance. A context already ended is refused with ctx.Err()
// before the blob is examined.
func (p *SoftwareProvider) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	root, err := p.liveRootLocked()
	if err != nil {
		return err
	}
	if root == nil {
		// This provider has protected nothing, so no blob can be its own.
		return ErrSealedAuthentication
	}

	kind, gen, err := parseBlobHeader(blob)
	if err != nil || kind != blobKindProvider || gen != 0 {
		return ErrSealedAuthentication
	}

	return swept(unwrapKey(root, blob, key))
}

// UnsealRoot implements [RootUnsealer]: it copies the provider root,
// generated at first use, into dst, which must be exactly [RootKeyBytes]
// long; any other length is [ErrInvalidSize]. A context already ended is
// refused with ctx.Err() before the root is generated or copied. The root
// then exists in two locked enclaves, the provider's and the Sealer's, and a
// shutdown sweep destroys both.
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

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
	"crypto/sha256"
	"errors"
	"sync"
)

// softwareProtectLimit is half of crypto/cipher's 2^32-message bound for one
// key under NewGCMWithRandomNonce, the same margin as kekMessageLimit.
const softwareProtectLimit = 1 << 31

// softwareProtectKeyInfo is the HKDF info that binds the key Protect wraps
// under to its one use, so it is never the root UnsealRoot exports.
const softwareProtectKeyInfo = "go-enclave v1 SoftwareProvider Protect key"

// SoftwareProvider is the pure-software provider, and the only one go-enclave
// ships. It implements [RootUnsealer] (the default for [ModeRootKey]),
// [KeyProtector] (AES-GCM under a key derived from the root, for tests and
// development of [ModePerOperation]) and [HealthReporter]. Its root is
// generated into a locked [Memory] at first use, and the Protect key,
// HKDF-SHA256 of the root under its own info, at the first Protect.
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
// Construct one with [NewSoftwareProvider]; the implementation is internal.
// A SoftwareProvider is safe for concurrent use.
type SoftwareProvider interface {
	KeyProtector
	RootUnsealer
	HealthReporter

	// Destroy releases the provider's root and Protect key. Every later call
	// fails closed with [ErrSealerDestroyed], so everything it protected, and
	// every [Sealer] that uses it, is unrecoverable. It waits for an
	// operation in progress, which is in-process and short. A release the
	// kernel refuses is reported and stays on the [WipeAll] ledger; calling
	// Destroy again retries it. Destroy is idempotent.
	Destroy() error
}

// softwareProvider is this package's [SoftwareProvider]. The zero value's
// methods report [ErrProviderNotConstructed], and a copy shares the
// original's root and lock.
type softwareProvider struct {
	_ noCopy
	s *softwareState
}

var _ SoftwareProvider = (*softwareProvider)(nil)

// softwareState is a [SoftwareProvider]'s mutable state, on the heap so that
// copies of the provider share it.
type softwareState struct {
	mu sync.Mutex
	// root is created on first use and retried on failure, since a
	// RLIMIT_MEMLOCK refusal can lift. Non-nil but dead means a sweep
	// destroyed it, and it must not be regenerated.
	root *Memory
	// protectKey is derived from root at the first Protect, and is dead
	// exactly when root is.
	protectKey *Memory
	// protects counts Protect attempts, charged before each so a failed one
	// still counts; only encryptions count against the bound.
	protects uint64
	// destroyed is set by Destroy and never cleared.
	destroyed bool
}

// SoftwareProvider serves both modes and reports its own sweep state.
var (
	_ KeyProtector   = (*softwareProvider)(nil)
	_ RootUnsealer   = (*softwareProvider)(nil)
	_ HealthReporter = (*softwareProvider)(nil)
)

// NewSoftwareProvider returns a software provider with no root yet; the root
// is generated at first use so that merely constructing one — which
// [NewSealer] does by default — costs no locked memory.
func NewSoftwareProvider() SoftwareProvider {
	return newSoftwareProvider()
}

// newSoftwareProvider is [NewSoftwareProvider] returning the implementation.
func newSoftwareProvider() *softwareProvider {
	return &softwareProvider{s: &softwareState{}}
}

// state returns the provider's shared state, or [ErrProviderNotConstructed]
// for one [NewSoftwareProvider] did not build.
func (p *softwareProvider) state() (*softwareState, error) {
	if p == nil || p.s == nil {
		return nil, ErrProviderNotConstructed
	}
	return p.s, nil
}

// rootLocked returns the root enclave, generating it on first use. The
// caller holds s.mu.
func (s *softwareState) rootLocked() (*Memory, error) {
	root, err := s.liveRootLocked()
	if err != nil || root != nil {
		return root, err
	}
	if root, err = newKeyEnclave(RootKeyBytes); err != nil {
		return nil, err
	}
	s.root = root
	return root, nil
}

// protectKeyLocked returns the Protect key, deriving it, and the root, on
// first use. The caller holds s.mu.
func (s *softwareState) protectKeyLocked() (*Memory, error) {
	root, err := s.rootLocked()
	if err != nil || s.protectKey != nil {
		return s.protectKey, err
	}
	k, err := deriveProtectKey(root)
	if err != nil {
		return nil, err
	}
	s.protectKey = k
	return k, nil
}

// deriveProtectKey derives the Protect key from root into a fresh locked
// enclave: HKDF-SHA256 under softwareProtectKeyInfo. The root is uniformly
// random, so no salt is needed; the info alone separates the two keys. The
// HKDF output and HMAC state are heap memory, wiped or erased as for an AES
// key schedule.
func deriveProtectKey(root *Memory) (*Memory, error) {
	k, err := newMemorySized(RootKeyBytes)
	if err != nil {
		return nil, err
	}
	if err := k.WithBytes(func(dst []byte) error {
		return root.WithBytes(func(r []byte) error {
			var herr error
			secretDo(func() {
				var b []byte
				if b, herr = hkdfKey(sha256.New, r, nil, softwareProtectKeyInfo, len(dst)); herr == nil {
					copy(dst, b)
					Wipe(b)
				}
			})
			if herr != nil {
				return &SealError{Cause: herr}
			}
			return nil
		})
	}); err != nil {
		return nil, destroyOnFailure(swept(err), k)
	}
	return k, nil
}

// liveRootLocked is the one statement of the provider's state: it reports
// [ErrSealerDestroyed] after Destroy, [ErrSealerWiped] once a shutdown sweep
// has destroyed the root or the Protect key, and otherwise the root, nil
// before first use. The caller holds s.mu.
func (s *softwareState) liveRootLocked() (*Memory, error) {
	switch {
	case s.destroyed:
		return nil, ErrSealerDestroyed
	case s.root != nil && !s.root.IsAlive(),
		s.protectKey != nil && !s.protectKey.IsAlive():
		return nil, ErrSealerWiped
	default:
		return s.root, nil
	}
}

// Health implements [HealthReporter]: it reports [ErrSealerDestroyed] after
// Destroy, [ErrSealerWiped] once a shutdown sweep has destroyed this
// provider's root, and nil otherwise, including when no root exists yet. It
// never generates a root.
func (p *softwareProvider) Health() error {
	s, err := p.state()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err = s.liveRootLocked()
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
// Protect key derived from the provider root, with the blob's frame bound as
// AAD.
//
// It returns ctx.Err() if ctx has already ended, [ErrProviderMessageLimit]
// once the key's encryption budget is spent, [ErrSealerWiped] after a
// shutdown sweep, and [ErrLockedMemoryUnavailable] if the root or the Protect
// key cannot be created on first use. A refused call charges nothing to the
// budget.
func (p *softwareProvider) Protect(ctx context.Context, key []byte) ([]byte, error) {
	s, err := p.state()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pk, err := s.protectKeyLocked()
	if err != nil {
		return nil, err
	}
	if s.protects >= softwareProtectLimit {
		return nil, ErrProviderMessageLimit
	}
	s.protects++

	// The frame's generation field is zero: this provider has one root.
	blob, err := wrapKey(pk, key, blobKindProvider, 0)
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
func (p *softwareProvider) Unprotect(ctx context.Context, blob, key []byte) error {
	s, err := p.state()
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.liveRootLocked(); err != nil {
		return err
	}
	if s.protectKey == nil {
		// This provider has protected nothing, so no blob can be its own.
		return ErrSealedAuthentication
	}

	kind, gen, err := parseBlobHeader(blob)
	if err != nil || kind != blobKindProvider || gen != 0 {
		return ErrSealedAuthentication
	}

	return swept(unwrapKey(s.protectKey, blob, key))
}

// UnsealRoot implements [RootUnsealer]: it copies the provider root,
// generated at first use, into dst, which must be exactly [RootKeyBytes]
// long; any other length is [ErrInvalidSize]. A context already ended is
// refused with ctx.Err() before the root is generated or copied. The root
// then exists in two locked enclaves, the provider's and the Sealer's, and a
// shutdown sweep destroys both. The root is never the key Protect uses.
func (p *softwareProvider) UnsealRoot(ctx context.Context, dst []byte) error {
	s, err := p.state()
	if err != nil {
		return err
	}
	if len(dst) != RootKeyBytes {
		return ErrInvalidSize
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	root, err := s.rootLocked()
	if err != nil {
		return err
	}
	return swept(root.WithBytes(func(b []byte) error {
		copyConstantTime(dst, b)
		return nil
	}))
}

// Destroy implements [SoftwareProvider.Destroy]; every copy is destroyed with
// it. It is safe on a nil or zero provider.
func (p *softwareProvider) Destroy() error {
	s, err := p.state()
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	s.destroyed = true
	return withCleanupFailure(nil, s.protectKey.Destroy(), s.root.Destroy())
}

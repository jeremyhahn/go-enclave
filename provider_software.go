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

// SoftwareProvider is the pure-software [RootUnsealer], [KeyProtector] and [HealthReporter]; its root lives in a memory enclave in this process.
type SoftwareProvider interface {
	KeyProtector
	RootUnsealer
	HealthReporter

	// Destroy releases the root and Protect key; every later call fails with [ErrSealerDestroyed].
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
	root *lockedRegion
	// protectKey is derived from root at the first Protect, and is dead
	// exactly when root is.
	protectKey *lockedRegion
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
func (s *softwareState) rootLocked() (*lockedRegion, error) {
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
func (s *softwareState) protectKeyLocked() (*lockedRegion, error) {
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

// deriveProtectKey derives the Protect key from root with HKDF-SHA256 under softwareProtectKeyInfo.
func deriveProtectKey(root *lockedRegion) (*lockedRegion, error) {
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

// liveRootLocked reports the provider's state and its root; the caller holds s.mu.
func (s *softwareState) liveRootLocked() (*lockedRegion, error) {
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

// Health implements [HealthReporter] and never generates a root.
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

// Protect implements [KeyProtector] with AES-GCM under the Protect key, the blob frame as AAD.
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

// Unprotect implements [KeyProtector], refusing anything its own Protect did not produce.
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

// UnsealRoot implements [RootUnsealer], copying the root into dst of exactly [RootKeyBytes].
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

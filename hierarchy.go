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
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"hash"
)

// kekBytes selects AES-256 for the key-encryption keys of [ModeRootKey].
const kekBytes = 32

// kekMessageLimit is how many DEKs one KEK generation may wrap before it is
// retired: half the 2^32 messages crypto/cipher allows a random-nonce GCM key.
const kekMessageLimit = 1 << 31

// maxKEKGenerations is how many KEK generations one wrapping key may wrap,
// the same bound as kekMessageLimit; it also keeps the uint32 generation
// counter from wrapping onto a retired generation whose blob is retained.
const maxKEKGenerations = 1 << 31

// wrappingSaltBytes matches the root length, so two sealers over the same
// root share a wrapping key only by a 256-bit salt collision.
const wrappingSaltBytes = 32

// wrappingKeyInfo is the HKDF info that binds a derived wrapping key to its
// one use.
const wrappingKeyInfo = "go-enclave v1 ModeRootKey KEK-wrapping key"

// hkdfKey is a test seam for an HKDF failure, which the standard library does
// not produce on demand.
var hkdfKey = hkdf.Key[hash.Hash]

// deriveWrappingKey replaces root, in place, with the key a [ModeRootKey]
// sealer wraps its KEK generations under: HKDF-SHA256 of the provider's root
// under a per-sealer salt. Every sealer over a provider, and every boot of a
// hardware root, gets the same root; the salt makes maxKEKGenerations bound
// a key no other sealer uses. The HKDF output and HMAC state are heap memory,
// wiped or erased as for an AES key schedule.
func deriveWrappingKey(root, salt []byte) error {
	var err error
	secretDo(func() {
		var k []byte
		if k, err = hkdfKey(sha256.New, root, salt, wrappingKeyInfo, len(root)); err == nil {
			copy(root, k)
			Wipe(k)
		}
	})
	if err != nil {
		return &SealError{Cause: err}
	}
	return nil
}

// hierarchyStateLocked is the one statement of a [ModeRootKey] sealer's
// state. It reports [ErrSealerDestroyed] after Destroy; otherwise whether a
// hierarchy is published, with [ErrSealerWiped] if it is and its root or
// current KEK is dead. Nothing is published before the first seal, nor ever
// in [ModePerOperation]. The caller holds s.mu (read is enough).
func (s *Sealer) hierarchyStateLocked() (published bool, err error) {
	switch {
	case s.destroyed:
		return false, ErrSealerDestroyed
	case s.root == nil:
		return false, nil
	case !s.root.IsAlive() || !s.kek.IsAlive():
		return true, ErrSealerWiped
	default:
		return true, nil
	}
}

// protectRootKey wraps the DEK under the current KEK generation, initializing
// or rotating first when needed. After either it loops, so the wrap always
// uses a generation re-read under the lock it runs under. The context is
// checked on every pass: an initialization that succeeded after the caller's
// context ended is kept, but that caller is told it was abandoned.
//
// protectRootKey and unprotectRootKey are the boundary every root-mode seal
// and open passes through, so their deferred withDeadHierarchyCleanup is the
// one place a dead hierarchy's key release is retried, and no exit skips it.
func (s *Sealer) protectRootKey(ctx context.Context, dek *MemoryEnclave) (blob []byte, err error) {
	defer func() { err = s.withDeadHierarchyCleanup(err) }()

	for {
		if err := contextFailure[sealFailed](ctx, nil); err != nil {
			return nil, err
		}

		s.mu.RLock()

		published, err := s.hierarchyStateLocked()
		if err != nil {
			s.mu.RUnlock()
			return nil, err
		}
		if !published {
			s.mu.RUnlock()
			if err := s.initHierarchy(ctx); err != nil {
				return nil, err
			}
			continue
		}

		// Reserved before wrapping, so a failed wrap still counts: rotating
		// slightly early is the safe direction.
		if s.kekUsed.Add(1) > s.kekLimit {
			s.mu.RUnlock()
			if err := s.rotateKEK(); err != nil {
				return nil, err
			}
			continue
		}

		err = dek.WithBytes(func(k []byte) error {
			var werr error
			blob, werr = wrapKey(s.kek, k, blobKindDEK, s.kekGen)
			return werr
		})
		// Translated before unlocking: a waiting rotation destroys the
		// outgoing KEK, which would then read as a sweep.
		err = hierarchyFailure(err, s.root, s.kek)
		s.mu.RUnlock()

		if err != nil {
			return nil, err
		}
		return blob, nil
	}
}

// unprotectRootKey recovers a DEK: current generation under the live KEK, a
// retired one by first unwrapping its retained blob under the root. It makes
// no provider call, so the context is unused.
func (s *Sealer) unprotectRootKey(_ context.Context, blob []byte, dek *MemoryEnclave) (err error) {
	// Deferred before the read lock is taken, so it runs once it is released.
	defer func() { err = s.withDeadHierarchyCleanup(err) }()

	s.mu.RLock()
	defer s.mu.RUnlock()

	published, err := s.hierarchyStateLocked()
	if err != nil {
		return err
	}
	if !published {
		// This sealer has sealed nothing, so no blob can be its own.
		return ErrSealedAuthentication
	}

	kind, gen, err := parseBlobHeader(blob)
	if err != nil || kind != blobKindDEK {
		return ErrSealedAuthentication
	}

	kek := s.kek
	if gen != s.kekGen {
		kekBlob, ok := s.kekBlobs[gen]
		if !ok {
			return ErrSealedAuthentication
		}
		retired, uerr := s.unwrapRetiredKEKLocked(kekBlob)
		if uerr != nil {
			return uerr
		}
		// Materialized for this one unwrap only.
		defer func() { _ = retired.Destroy() }()
		kek = retired
	}

	return hierarchyFailure(dek.WithBytes(func(k []byte) error {
		return unwrapKey(kek, blob, k)
	}), s.root, s.kek)
}

// withDeadHierarchyCleanup returns err unchanged unless it reports
// ErrSealerWiped and the published hierarchy is dead; then it retries the
// release of the hierarchy's keys and joins any refusal. The caller must not
// hold s.mu.
func (s *Sealer) withDeadHierarchyCleanup(err error) error {
	if !errors.Is(err, ErrSealerWiped) {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, state := s.hierarchyStateLocked(); !errors.Is(state, ErrSealerWiped) {
		return err
	}
	return withCleanupFailure(err, destroyAll(s.kek, s.root))
}

// unwrapRetiredKEKLocked recovers a retired KEK generation into a fresh locked
// enclave the caller must destroy. The caller holds s.mu (read is enough) and
// has verified the hierarchy is alive.
func (s *Sealer) unwrapRetiredKEKLocked(kekBlob []byte) (*MemoryEnclave, error) {
	kek, err := NewMemoryEnclaveSized(kekBytes)
	if err != nil {
		return nil, err
	}
	if err := kek.WithBytes(func(k []byte) error {
		return unwrapKey(s.root, kekBlob, k)
	}); err != nil {
		_ = kek.Destroy()
		return nil, hierarchyFailure(err, s.root, s.kek)
	}
	return kek, nil
}

// hierarchyFailure turns an [ErrEnclaveDestroyed] into [ErrSealerWiped] only
// when one of the given hierarchy keys is dead. A dead per-call enclave (the
// DEK, or a materialized retired KEK) stays ErrEnclaveDestroyed: the
// hierarchy is intact. Hierarchy keys are used only under s.mu or by the
// initSlot holder, and neither destroys one in use, so a dead one is a
// sweep's doing. Callers under s.mu pass the root and current KEK read under
// it, so a rotation cannot change them between a failure and its
// translation.
func hierarchyFailure(err error, hierarchy ...*MemoryEnclave) error {
	if !errors.Is(err, ErrEnclaveDestroyed) {
		return err
	}
	for _, k := range hierarchy {
		if k != nil && !k.IsAlive() {
			return ErrSealerWiped
		}
	}
	return err
}

// initHierarchy performs the once-per-sealer root unseal and mints the first
// KEK generation. It is retried rather than memoized with sync.Once, because
// a memlock ceiling or transient provider failure can lift. A failed unseal
// is retried with a fresh UnsealRoot call; a successful unseal followed by a
// failed mint keeps the root in pendingRoot and retries only the mint.
//
// The unseal and mint run holding initSlot and nothing else; mu is
// write-locked only to publish root, KEK and generation map as one state. A
// caller queued behind a successful initializer finds the hierarchy published
// and does not call the provider.
//
// A sweep overlapping the initialization leaves the sealer wiped: the sweep
// sequence is read before the unseal and checked before the mint, after a
// failed mint, and at publication. On overlap the root and any KEK are
// destroyed rather than published, the dead root stays in pendingRoot, and
// every later attempt reports [ErrSealerWiped] without asking the provider.
func (s *Sealer) initHierarchy(ctx context.Context) (err error) {
	select {
	case s.initSlot <- struct{}{}:
	case <-ctx.Done():
		return contextFailure[sealFailed](ctx, nil)
	}
	// Released under mu, so a Destroy that found the slot taken is seen here
	// and its pending keys released; a destroyed sealer reports only that.
	defer func() {
		err = initFailure(ctx, err)
		s.mu.Lock()
		if s.destroyed {
			err = withCleanupFailure(ErrSealerDestroyed, s.releasePending())
		}
		<-s.initSlot
		s.mu.Unlock()
	}()

	// select picks randomly among ready cases, so an ended context can still
	// win the slot.
	if err := contextFailure[sealFailed](ctx, nil); err != nil {
		return err
	}

	// Decided already: a live hierarchy is used, and a swept one must not be
	// rebuilt.
	s.mu.RLock()
	published, err := s.hierarchyStateLocked()
	s.mu.RUnlock()
	if published || err != nil {
		return err
	}

	root := s.pendingRoot
	if root == nil {
		if root, err = s.unsealRoot(ctx); err != nil {
			return err
		}
	}

	// The overlap check runs first so a root whose release was refused on an
	// earlier attempt is retried, not only reported dead.
	if err := s.discardIfSwept(nil); err != nil {
		return err
	}
	if !root.IsAlive() {
		return ErrSealerWiped
	}

	kek, blob, err := newGeneration(root, 1)
	if err != nil {
		if derr := s.discardIfSwept(err); derr != nil {
			return derr
		}
		// root stays in pendingRoot; the next attempt mints again under it.
		return err
	}

	s.pendingKEK = kek

	// Unlocked before the deferred slot release above takes mu again.
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.destroyed {
		return ErrSealerDestroyed // the slot release releases the pending keys
	}
	if err := s.discardIfSwept(nil); err != nil {
		return err
	}

	// Published together, so no reader observes a root without its KEK.
	s.root = root
	s.pendingRoot, s.pendingKEK = nil, nil
	s.kek, s.kekGen = kek, 1
	s.kekBlobs = map[uint32][]byte{1: blob}
	s.kekUsed.Store(0)
	return nil
}

// unsealRoot asks the provider for the root and replaces it, within the same
// borrow, by the derived wrapping key, which it leaves in pendingRoot with
// the sweep sequence read before the unseal in pendingGen. The caller holds
// initSlot.
func (s *Sealer) unsealRoot(ctx context.Context) (*MemoryEnclave, error) {
	// Read before the root exists, as Seal reads sealedAtGen.
	gen := sweepGeneration()

	// Drawn before the unseal, so nothing can fail for want of it once
	// UnsealRoot has succeeded.
	salt := make([]byte, wrappingSaltBytes)
	if err := fillRandom(salt); err != nil {
		return nil, &SealError{Cause: err}
	}
	root, err := NewMemoryEnclaveSized(RootKeyBytes)
	if err != nil {
		return nil, err
	}
	// The provider writes the root directly into locked pages, and within the
	// same borrow it is replaced by the derived wrapping key, so no sweep can
	// interleave.
	unsealed := false
	if err := root.WithBytes(func(b []byte) error {
		uerr := s.ru.UnsealRoot(ctx, b)
		if uerr == nil {
			unsealed = true
			return deriveWrappingKey(b, salt)
		}
		if cerr := contextFailure[sealFailed](ctx, uerr); cerr != nil {
			return cerr
		}
		return uerr
	}); err != nil {
		if unsealed {
			// The unseal may not be repeated but no key was derived: retain
			// the root dead, so this sealer reports itself wiped.
			s.pendingRoot, s.pendingGen = root, gen
			return nil, destroyOnFailure(&SealerWipedError{Cause: err}, root)
		}
		// The unseal itself failed, so it may be asked again.
		_ = root.Destroy()
		return nil, providerFailure[sealFailed](err)
	}
	// The unseal succeeded, even if the context ended meanwhile: the root is
	// retained and published, and the caller is told of its context by
	// initFailure or protectRootKey's next pass.
	s.pendingRoot, s.pendingGen = root, gen
	return root, nil
}

// initFailure joins a slot holder's failure with the caller's ended context,
// so neither the abandonment nor the cause is lost. An error that already
// carries both is returned as is.
func initFailure(ctx context.Context, err error) error {
	ended := ctx.Err()
	if err == nil || ended == nil || (errors.Is(err, ErrSealFailed) && errors.Is(err, ended)) {
		return err
	}
	return contextFailure[sealFailed](ctx, err)
}

// discardIfSwept returns nil unless a sweep has overlapped the initialization
// that produced pendingRoot (the sequence moved since pendingGen, or was odd
// then). If one has, it releases the pending keys and returns
// [ErrSealerWiped] (a [SealerWipedError] carrying cause, the failure that
// prompted the check, when it is non-nil), with any refused release. Since
// the sequence never returns to pendingGen, every later attempt retries a
// refused release. The caller holds initSlot.
func (s *Sealer) discardIfSwept(cause error) error {
	if !sweepInFlight(s.pendingGen) && sweepGeneration() == s.pendingGen {
		return nil
	}
	return withCleanupFailure(withCause[sealerWiped](cause), s.releasePending())
}

// releasePending destroys pendingKEK and pendingRoot. Once both are released
// pendingKEK is cleared; pendingRoot is kept, dead, as the wiped state of a
// hierarchy never published (a destroyed sealer reports ErrSealerDestroyed
// before it). A release the kernel refuses keeps its reference, so a later
// call retries it. The caller holds initSlot.
func (s *Sealer) releasePending() error {
	err := destroyAll(s.pendingKEK, s.pendingRoot)
	if err == nil {
		s.pendingKEK = nil
	}
	return err
}

// rotateKEK retires the current KEK generation and mints the next. The
// outgoing KEK's enclave is destroyed (the write lock excludes in-flight
// users) and its root-wrapped blob stays in kekBlobs so values sealed under
// it keep opening. Holding mu across the mint is allowed because rotation
// never calls the provider.
func (s *Sealer) rotateKEK() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Read before any liveness check, so a sweep that runs at any point from
	// here on shows up as an odd value now or a different one after the mint.
	gen := sweepGeneration()

	published, err := s.hierarchyStateLocked()
	switch {
	case errors.Is(err, ErrSealerWiped):
		return withCleanupFailure(err, destroyAll(s.kek, s.root))
	case err != nil:
		return err
	case !published:
		// Unreachable: only a seal that found the hierarchy initialized asks
		// for rotation.
		return &SealError{Cause: errHierarchyUninitialized}
	case s.kekUsed.Load() <= s.kekLimit:
		// Another goroutine rotated while this one waited for the lock.
		return nil
	case s.kekGen >= maxKEKGenerations:
		return &SealError{Cause: ErrSealerExhausted}
	}

	// WipeAll skips the root while newGeneration borrows it, so a sweep here
	// could kill only the old KEK; publishing the new generation would then
	// re-key after a WipeAll. Any overlap wipes the whole hierarchy, the
	// unpublished generation included. A refused key is already wiped and
	// stays on the WipeAll ledger; the sealer also retries its published root
	// and KEK whenever a seal or open finds the hierarchy dead.
	kek, blob, err := newGeneration(s.root, s.kekGen+1)
	if sweepInFlight(gen) || sweepGeneration() != gen {
		return withCleanupFailure(withCause[sealerWiped](err), destroyAll(kek, s.kek, s.root))
	}
	if err != nil {
		// The current generation stays; the next seal retries the rotation.
		return err
	}

	_ = s.kek.Destroy()
	s.kek, s.kekGen = kek, s.kekGen+1
	s.kekBlobs[s.kekGen] = blob
	s.kekUsed.Store(0)
	return nil
}

// newGeneration mints KEK generation gen: a fresh key in locked memory, plus
// that key wrapped under the root for retention after retirement.
func newGeneration(root *MemoryEnclave, gen uint32) (*MemoryEnclave, []byte, error) {
	kek, err := newKeyEnclave(kekBytes)
	if err != nil {
		return nil, nil, err
	}

	var blob []byte
	if err := kek.WithBytes(func(k []byte) error {
		var werr error
		blob, werr = wrapKey(root, k, blobKindKEK, gen)
		return werr
	}); err != nil {
		return nil, nil, destroyOnFailure(hierarchyFailure(err, root), kek)
	}
	return kek, blob, nil
}

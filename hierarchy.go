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
	"sync/atomic"
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

// deriveWrappingKey replaces root in place with HKDF-SHA256 of the provider's root under a per-sealer salt.
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

// hierarchyStateLocked reports a [ModeRootKey] sealer's state; the caller holds s.mu.
func (s *sealerState) hierarchyStateLocked() (published bool, err error) {
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

// protectRootKey wraps the DEK under the current KEK generation, initializing or rotating first when needed.
func (s *sealerState) protectRootKey(ctx context.Context, dek *lockedRegion) (blob []byte, err error) {
	defer func() { err = s.withDeadHierarchyCleanup(err) }()

	for {
		if err := contextFailure[SealError](ctx, nil); err != nil {
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
			if err := s.rotateKEK(ctx); err != nil {
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
		if err == nil {
			// Counted under the lock that pins the generation, so a rotation
			// sees this value before deciding the outgoing blob is unused.
			s.kekRefs[s.kekGen].Add(1)
		}
		s.mu.RUnlock()

		if err != nil {
			return nil, err
		}
		return blob, nil
	}
}

// releaseBlob drops a value's reference on its KEK generation, and a retired generation with its last value.
func (s *sealerState) releaseBlob(blob []byte) {
	if s.mode != ModeRootKey {
		return
	}
	kind, gen, err := parseBlobHeader(blob)
	if err != nil || kind != blobKindDEK {
		return
	}

	s.mu.RLock()
	refs := s.kekRefs[gen]
	last := refs != nil && refs.Add(-1) == 0 && gen != s.kekGen
	s.mu.RUnlock()
	if !last {
		return
	}

	// No value can take a new reference on a retired generation, so the
	// count stays zero until the write lock is held.
	s.mu.Lock()
	s.dropIfUnusedLocked(gen)
	s.mu.Unlock()
}

// dropIfUnusedLocked wipes and forgets the root-wrapped KEK of generation gen
// if it is retired and no live value was sealed under it. Called with mu
// write-locked.
func (s *sealerState) dropIfUnusedLocked(gen uint32) {
	refs := s.kekRefs[gen]
	if gen == s.kekGen || refs == nil || refs.Load() != 0 {
		return
	}
	Wipe(s.kekBlobs[gen])
	delete(s.kekBlobs, gen)
	delete(s.kekRefs, gen)
}

// unprotectRootKey recovers a DEK: current generation under the live KEK, a
// retired one by first unwrapping its retained blob under the root. It makes
// no provider call, so the context is unused.
func (s *sealerState) unprotectRootKey(_ context.Context, blob []byte, dek *lockedRegion) (err error) {
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

// withDeadHierarchyCleanup retries the release of a dead hierarchy's keys on ErrSealerWiped; the caller must not hold s.mu.
func (s *sealerState) withDeadHierarchyCleanup(err error) error {
	if !errors.Is(err, ErrSealerWiped) {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, state := s.hierarchyStateLocked(); !errors.Is(state, ErrSealerWiped) {
		return err
	}
	return withCleanupFailure(err, destroyKeys(s.kek, s.root))
}

// unwrapRetiredKEKLocked recovers a retired KEK generation into a fresh locked enclave; the caller holds s.mu.
func (s *sealerState) unwrapRetiredKEKLocked(kekBlob []byte) (*lockedRegion, error) {
	kek, err := newMemorySized(kekBytes)
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

// hierarchyFailure turns [ErrEnclaveDestroyed] into [ErrSealerWiped] only when a hierarchy key is dead.
func hierarchyFailure(err error, hierarchy ...Handle) error {
	if !errors.Is(err, ErrEnclaveDestroyed) {
		return err
	}
	for _, k := range hierarchy {
		if !isNilInterface(k) && !k.IsAlive() {
			return ErrSealerWiped
		}
	}
	return err
}

// destroyKeys destroys every non-nil hierarchy key and returns every refused release.
func destroyKeys(keys ...Handle) error {
	var refused []error
	for _, k := range keys {
		if !isNilInterface(k) {
			refused = append(refused, k.Destroy())
		}
	}
	return withCleanupFailure(nil, refused...)
}

// importKey moves src's key into s's importer for AES-256-GCM wrapping and destroys src; the caller must not hold s.mu.
func importKey[E causeShape, P causeError[E]](ctx context.Context, s *sealerState, src *lockedRegion) (Handle, error) {
	var h Handle
	err := src.WithBytes(func(k []byte) error {
		var ierr error
		h, ierr = s.importer.Import(ctx, k, WithPurpose(PurposeWrappingKey), WithAlgorithm(AlgorithmAES256GCM))
		return ierr
	})
	// Import wiped the pages on every path; a release the kernel refuses
	// stays on the WipeAll ledger.
	_ = src.Destroy()

	if err != nil {
		if cerr := contextFailure[E, P](ctx, err); cerr != nil {
			err = cerr
		} else {
			err = backendFailure[E, P](err)
		}
		return nil, s.destroyOrRetain(err, h)
	}

	refused := &CapabilityError{Backend: s.importer.Name(), Capability: CapabilityAEAD}
	if isNilInterface(h) {
		return nil, refused
	}
	_, device := h.(AEAD)
	_, inProcess := h.(ByteAccess)
	if !device && !inProcess {
		return nil, s.destroyOrRetain(refused, h)
	}
	return h, nil
}

// backendFailure is providerFailure for a backend's error, which keeps the
// seam's own refusals as they are.
func backendFailure[E causeShape, P causeError[E]](err error) error {
	if errors.Is(err, ErrCapabilityUnsupported) || errors.Is(err, ErrInvalidImport) {
		return err
	}
	return providerFailure[E, P](err)
}

// initHierarchy unseals the root and mints the first KEK generation, retried rather than memoized; an overlapping sweep leaves the sealer wiped.
func (s *sealerState) initHierarchy(ctx context.Context) (err error) {
	select {
	case s.initSlot <- struct{}{}:
	case <-ctx.Done():
		return contextFailure[SealError](ctx, nil)
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
	if err := contextFailure[SealError](ctx, nil); err != nil {
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

	wrap := s.pendingWrap
	if wrap == nil {
		if wrap, err = s.wrappingKey(ctx, root); err != nil {
			if derr := s.discardIfSwept(err); derr != nil {
				return derr
			}
			// root stays in pendingRoot; the next attempt imports again.
			return err
		}
		s.pendingWrap = wrap
	}

	kek, blob, err := s.firstGeneration(ctx, wrap)
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
	s.root = wrap
	s.pendingWrap, s.pendingKEK = nil, nil
	// An imported wrapping key leaves its locked source behind; a release
	// the kernel refuses keeps it pending, for Destroy to retry.
	if s.importer == nil || root.Destroy() == nil {
		s.pendingRoot = nil
	}
	s.kek, s.kekGen = kek, 1
	s.kekBlobs = map[uint32][]byte{1: blob}
	s.kekRefs = map[uint32]*atomic.Int64{1: new(atomic.Int64)}
	s.kekUsed.Store(0)
	return nil
}

// wrappingKey is the wrapping key root holds, where the sealer keeps it:
// root itself, or a copy of it imported into the backend. The copy leaves
// root intact, so a failed import can be retried.
func (s *sealerState) wrappingKey(ctx context.Context, root *lockedRegion) (Handle, error) {
	if s.importer == nil {
		return root, nil
	}
	cp, err := newMemorySized(root.Size())
	if err != nil {
		return nil, err
	}
	if err := root.WithBytes(func(r []byte) error {
		return cp.WithBytes(func(c []byte) error {
			copy(c, r)
			return nil
		})
	}); err != nil {
		return nil, destroyOnFailure(hierarchyFailure(err, root), cp)
	}
	return importKey[SealError](ctx, s, cp)
}

// firstGeneration mints KEK generation 1 under wrap, imported into the
// backend when the sealer has one.
func (s *sealerState) firstGeneration(ctx context.Context, wrap Handle) (Handle, []byte, error) {
	kek, blob, err := newGeneration(wrap, 1)
	if err != nil {
		return nil, nil, err
	}
	if s.importer == nil {
		return kek, blob, nil
	}
	h, err := importKey[SealError](ctx, s, kek)
	if err != nil {
		return nil, nil, err
	}
	return h, blob, nil
}

// unsealRoot asks the provider for the root and replaces it with the derived wrapping key; the caller holds initSlot.
func (s *sealerState) unsealRoot(ctx context.Context) (*lockedRegion, error) {
	// Read before the root exists, as Seal reads sealedAtGen.
	gen := sweepGeneration()

	// Drawn before the unseal, so nothing can fail for want of it once
	// UnsealRoot has succeeded.
	salt := make([]byte, wrappingSaltBytes)
	if err := fillRandom(salt); err != nil {
		return nil, &SealError{Cause: err}
	}
	root, err := newMemorySized(RootKeyBytes)
	if err != nil {
		return nil, err
	}
	// The provider writes the root directly into locked pages, and within the
	// same borrow it is replaced by the derived wrapping key, so no sweep can
	// interleave.
	unsealed := false
	err = root.WithBytes(func(b []byte) error {
		uerr := s.ru.UnsealRoot(ctx, b)
		if uerr == nil {
			unsealed = true
			return deriveWrappingKey(b, salt)
		}
		if cerr := contextFailure[SealError](ctx, uerr); cerr != nil {
			return cerr
		}
		return uerr
	})
	if unsealed {
		// The default provider's root has served its one unseal: only the
		// key derived from it is used from here on. A release the kernel
		// refuses stays on the WipeAll ledger, and Destroy retries it.
		_ = s.owned.Destroy()
	}
	if err != nil {
		if unsealed {
			// The unseal may not be repeated but no key was derived: retain
			// the root dead, so this sealer reports itself wiped.
			s.pendingRoot, s.pendingGen = root, gen
			return nil, destroyOnFailure(&SealerWipedError{Cause: err}, root)
		}
		// The unseal itself failed, so it may be asked again.
		_ = root.Destroy()
		return nil, providerFailure[SealError](err)
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
	return contextFailure[SealError](ctx, err)
}

// discardIfSwept releases the pending keys and returns [ErrSealerWiped] if a sweep overlapped initialization; the caller holds initSlot.
func (s *sealerState) discardIfSwept(cause error) error {
	if !sweepInFlight(s.pendingGen) && sweepGeneration() == s.pendingGen {
		return nil
	}
	return withCleanupFailure(withCause[SealerWipedError](cause), s.releasePending())
}

// releasePending destroys the pending keys, keeping refused releases for retry; the caller holds initSlot.
func (s *sealerState) releasePending() error {
	err := destroyKeys(s.pendingKEK, s.pendingWrap, s.pendingRoot)
	if err == nil {
		s.pendingKEK = nil
	}
	return err
}

// rotateKEK retires the current KEK generation and mints the next.
func (s *sealerState) rotateKEK(ctx context.Context) error {
	s.mu.Lock()

	// Read before any liveness check, so a sweep that runs at any point from
	// here on shows up as an odd value now or a different one after the mint.
	gen := sweepGeneration()

	kek, blob, err := s.mintNextLocked(gen)
	if err != nil || kek == nil {
		s.mu.Unlock()
		return err
	}
	if s.importer == nil {
		err := s.publishNextLocked(kek, blob)
		s.mu.Unlock()
		return err
	}
	next := s.kekGen + 1
	s.mu.Unlock()

	// Imported with mu released, as a device may block; seals under the
	// current generation go on meanwhile. A failure keeps that generation,
	// and the next seal retries the rotation.
	h, err := importKey[SealError](ctx, s, kek)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case s.destroyed:
		return s.destroyOrRetainLocked(ErrSealerDestroyed, h)
	case sweepInFlight(gen) || sweepGeneration() != gen:
		return withCleanupFailure(s.destroyOrRetainLocked(withCause[SealerWipedError](nil), h), destroyKeys(s.kek, s.root))
	case s.kekGen+1 != next:
		// Another seal rotated meanwhile; its generation stands.
		return s.destroyOrRetainLocked(nil, h)
	}
	return s.publishNextLocked(h, blob)
}

// mintNextLocked mints the next KEK generation in locked memory, wrapped
// under the root, or returns a nil KEK when no rotation is due. Called with mu
// write-locked; gen is the sweep sequence read when it was taken.
func (s *sealerState) mintNextLocked(gen uint64) (*lockedRegion, []byte, error) {
	published, err := s.hierarchyStateLocked()
	switch {
	case errors.Is(err, ErrSealerWiped):
		return nil, nil, withCleanupFailure(err, destroyKeys(s.kek, s.root))
	case err != nil:
		return nil, nil, err
	case !published:
		// Unreachable: only a seal that found the hierarchy initialized asks
		// for rotation.
		return nil, nil, &SealError{Cause: errHierarchyUninitialized}
	case s.kekUsed.Load() <= s.kekLimit:
		// Another goroutine rotated while this one waited for the lock.
		return nil, nil, nil
	case s.kekGen >= maxKEKGenerations:
		return nil, nil, &SealError{Cause: ErrSealerExhausted}
	}

	// Any overlapping sweep wipes the whole hierarchy, the unpublished generation included.
	kek, blob, err := newGeneration(s.root, s.kekGen+1)
	if sweepInFlight(gen) || sweepGeneration() != gen {
		return nil, nil, withCleanupFailure(withCause[SealerWipedError](err), destroyKeys(kek, s.kek, s.root))
	}
	// On failure the current generation stays; the next seal retries.
	return kek, blob, err
}

// publishNextLocked makes kek the current generation and destroys the outgoing one; called with mu write-locked.
func (s *sealerState) publishNextLocked(kek Handle, blob []byte) error {
	outgoing := s.kekGen
	err := s.destroyOrRetainLocked(nil, s.kek)
	s.kek, s.kekGen = kek, s.kekGen+1
	s.kekBlobs[s.kekGen] = blob
	s.kekRefs[s.kekGen] = new(atomic.Int64)
	s.kekUsed.Store(0)
	s.dropIfUnusedLocked(outgoing)
	return err
}

// newGeneration mints KEK generation gen: a fresh key in locked memory, plus
// that key wrapped under the root for retention after retirement.
func newGeneration(root Handle, gen uint32) (*lockedRegion, []byte, error) {
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

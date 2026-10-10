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

// protectRootKey wraps the DEK under the current KEK generation, initializing
// or rotating first when needed. After either it loops, so the wrap always
// uses a generation re-read under the lock it runs under. The context is
// checked on every pass: an initialization that succeeded after the caller's
// context ended is kept, but that caller is told it was abandoned.
//
// protectRootKey and unprotectRootKey are the boundary every root-mode seal
// and open passes through, so their deferred withDeadHierarchyCleanup is the
// one place a dead hierarchy's key release is retried, and no exit skips it.
func (s *sealerState) protectRootKey(ctx context.Context, dek *Memory) (blob []byte, err error) {
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

// releaseBlob ends the reference a value sealed under blob holds on its KEK
// generation (see kekRefs), and drops a retired generation with its last
// value. It is a no-op outside ModeRootKey, once the sealer is destroyed, and
// for a blob that is not one of this sealer's DEK blobs.
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
func (s *sealerState) unprotectRootKey(_ context.Context, blob []byte, dek *Memory) (err error) {
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

// unwrapRetiredKEKLocked recovers a retired KEK generation into a fresh locked
// enclave the caller must destroy. The caller holds s.mu (read is enough) and
// has verified the hierarchy is alive. It stays in locked memory even under
// WithBackend: importing would be a blocking device call under mu, for one
// unwrap of a generation that was itself minted in locked memory.
func (s *sealerState) unwrapRetiredKEKLocked(kekBlob []byte) (*Memory, error) {
	kek, err := NewMemorySized(kekBytes)
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

// destroyKeys destroys every key of the hierarchy, which may be handles of
// the sealer's backend, skipping nil ones, and returns every release the
// kernel refused. A refused key is already wiped and stays on the [WipeAll]
// ledger; destroying it again retries the release, and destroying a released
// one again is a no-op.
func destroyKeys(keys ...Handle) error {
	var errs error
	for _, k := range keys {
		if !isNilInterface(k) {
			errs = withCleanupFailure(errs, k.Destroy())
		}
	}
	return errs
}

// importKey moves the key src holds into s's importer, for wrapping with
// AES-256-GCM, and destroys src on every path. A backend's own failure is a
// failure of kind K; a handle the sealer cannot wrap with, one with neither
// AEAD nor ByteAccess, is destroyed and refused. A handle that refuses that
// Destroy is retained (destroyOrRetain). The caller must not hold s.mu.
func importKey[K kind](ctx context.Context, s *sealerState, src *Memory) (Handle, error) {
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
		if cerr := contextFailure[K](ctx, err); cerr != nil {
			err = cerr
		} else {
			err = backendFailure[K](err)
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
func backendFailure[K kind](err error) error {
	if errors.Is(err, ErrCapabilityUnsupported) || errors.Is(err, ErrInvalidImport) {
		return err
	}
	return providerFailure[K](err)
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
func (s *sealerState) initHierarchy(ctx context.Context) (err error) {
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
func (s *sealerState) wrappingKey(ctx context.Context, root *Memory) (Handle, error) {
	if s.importer == nil {
		return root, nil
	}
	cp, err := NewMemorySized(root.Size())
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
	return importKey[sealFailed](ctx, s, cp)
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
	h, err := importKey[sealFailed](ctx, s, kek)
	if err != nil {
		return nil, nil, err
	}
	return h, blob, nil
}

// unsealRoot asks the provider for the root and replaces it, within the same
// borrow, by the derived wrapping key, which it leaves in pendingRoot with
// the sweep sequence read before the unseal in pendingGen. The caller holds
// initSlot.
func (s *sealerState) unsealRoot(ctx context.Context) (*Memory, error) {
	// Read before the root exists, as Seal reads sealedAtGen.
	gen := sweepGeneration()

	// Drawn before the unseal, so nothing can fail for want of it once
	// UnsealRoot has succeeded.
	salt := make([]byte, wrappingSaltBytes)
	if err := fillRandom(salt); err != nil {
		return nil, &SealError{Cause: err}
	}
	root, err := NewMemorySized(RootKeyBytes)
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
		if cerr := contextFailure[sealFailed](ctx, uerr); cerr != nil {
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
func (s *sealerState) discardIfSwept(cause error) error {
	if !sweepInFlight(s.pendingGen) && sweepGeneration() == s.pendingGen {
		return nil
	}
	return withCleanupFailure(withCause[sealerWiped](cause), s.releasePending())
}

// releasePending destroys pendingKEK, pendingWrap and pendingRoot. Once all
// are released pendingKEK is cleared; pendingWrap and pendingRoot are kept,
// dead, as the wiped state of a
// hierarchy never published (a destroyed sealer reports ErrSealerDestroyed
// before it). A release the kernel refuses keeps its reference, so a later
// call retries it. The caller holds initSlot.
func (s *sealerState) releasePending() error {
	err := destroyKeys(s.pendingKEK, s.pendingWrap, s.pendingRoot)
	if err == nil {
		s.pendingKEK = nil
	}
	return err
}

// rotateKEK retires the current KEK generation and mints the next. The
// outgoing KEK's enclave is destroyed (the write lock excludes in-flight
// users) and its root-wrapped blob stays in kekBlobs while values sealed
// under it are alive, so they keep opening. Holding mu across the mint is
// allowed because the mint never calls the provider; the import WithBackend
// adds runs with mu released.
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
	h, err := importKey[sealFailed](ctx, s, kek)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch {
	case s.destroyed:
		return s.destroyOrRetainLocked(ErrSealerDestroyed, h)
	case sweepInFlight(gen) || sweepGeneration() != gen:
		return withCleanupFailure(s.destroyOrRetainLocked(withCause[sealerWiped](nil), h), destroyKeys(s.kek, s.root))
	case s.kekGen+1 != next:
		// Another seal rotated meanwhile; its generation stands.
		return s.destroyOrRetainLocked(nil, h)
	}
	return s.publishNextLocked(h, blob)
}

// mintNextLocked mints the next KEK generation in locked memory, wrapped
// under the root, or returns a nil KEK when no rotation is due. Called with mu
// write-locked; gen is the sweep sequence read when it was taken.
func (s *sealerState) mintNextLocked(gen uint64) (*Memory, []byte, error) {
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

	// WipeAll skips the root while newGeneration borrows it, so a sweep here
	// could kill only the old KEK; publishing the new generation would then
	// re-key after a WipeAll. Any overlap wipes the whole hierarchy, the
	// unpublished generation included. A refused key is already wiped and
	// stays on the WipeAll ledger; the sealer also retries its published root
	// and KEK whenever a seal or open finds the hierarchy dead.
	kek, blob, err := newGeneration(s.root, s.kekGen+1)
	if sweepInFlight(gen) || sweepGeneration() != gen {
		return nil, nil, withCleanupFailure(withCause[sealerWiped](err), destroyKeys(kek, s.kek, s.root))
	}
	// On failure the current generation stays; the next seal retries.
	return kek, blob, err
}

// publishNextLocked makes kek, whose root-wrapped form is blob, the current
// generation, destroys the outgoing KEK, and drops the outgoing generation's
// root-wrapped blob if no live value needs it. An outgoing KEK that refuses
// its Destroy is retained (destroyOrRetainLocked) until a Destroy releases it,
// and its [CleanupError] returned: the new generation is published all the
// same. Called with mu write-locked.
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
func newGeneration(root Handle, gen uint32) (*Memory, []byte, error) {
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

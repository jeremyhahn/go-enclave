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
	"sync"
)

// Sealed holds material encrypted at rest and decrypts it into a new memory enclave only on [Sealed.Open]; see [Mode] for what each mode exposes.
type Sealed interface {
	// Open decrypts the material into a new memory enclave the caller must Destroy; ctx bounds the open.
	Open(ctx context.Context) (ByteAccess, error)

	// OpenIn is [Sealed.Open] into backend b, admitted against b's budget before anything is decrypted.
	OpenIn(ctx context.Context, b Backend) (Handle, error)

	// IsAlive reports whether [Sealed.Destroy] has not run; use [Sealed.Openable] to know whether it can open.
	IsAlive() bool

	// Openable reports, without opening, whether anything known prevents [Sealed.Open] from recovering the material.
	Openable() error

	// Destroy wipes the sealed material once opens in flight finish; it is idempotent and always returns nil.
	Destroy() error
}

// sealedValue is this package's [Sealed]; a nil receiver is valid and it must not be copied.
type sealedValue struct {
	_ noCopy

	*sealedState
}

var _ Sealed = (*sealedValue)(nil)

// sealedState is everything a [Sealed] holds; nil in a zero Sealed.
type sealedState struct {
	mu sync.RWMutex

	// sealer is nil'd on Destroy so a destroyed value does not pin a Sealer.
	sealer *envelopeSealer

	// sealed is nonce || ciphertext || tag under the DEK; nil once destroyed.
	sealed []byte

	// blob is the wrapped DEK, bound into sealed's AAD by sealedAAD.
	blob []byte

	// version is the envelope version, which selects the AAD (sealedAAD).
	// The zero value is contract v1. Written once at construction, so opens
	// read it without the lock.
	version uint8

	// size is the plaintext length; Open sizes its destination exactly so the
	// AEAD cannot allocate.
	size int

	// opens counts opens in flight, which use the envelope with mu released.
	// While it is non-zero Destroy leaves the wipe to the last open out.
	// Guarded by mu.
	opens int

	// sealedAtGen is the sweep generation at seal time. Written once at
	// construction, so Openable reads it without the lock.
	sealedAtGen uint64
}

// Envelope versions (docs/sealing/engineering.md, "Envelope version").
const (
	// sealedVersionV1 is contract v1, the form without a version byte: the
	// AAD is the whole blob.
	sealedVersionV1 uint8 = 0

	// sealedVersionV2 binds the version byte into the AAD ahead of the blob.
	sealedVersionV2 uint8 = 2

	// sealedVersionCurrent is the version every new seal writes.
	sealedVersionCurrent = sealedVersionV2
)

// sealedAAD returns a fresh copy of the AAD an envelope of version binds:
// the blob for contract v1, the version byte then the blob from version 2
// on. The caller wipes it. An unknown version is ErrUnknownSealedVersion.
func sealedAAD(version uint8, blob []byte) ([]byte, error) {
	switch version {
	case sealedVersionV1:
		return append([]byte(nil), blob...), nil
	case sealedVersionV2:
		return append([]byte{version}, blob...), nil
	}
	return nil, ErrUnknownSealedVersion
}

// NewSealed seals data under the process [Sealer], wiping the caller's slice; ctx bounds every blocking step.
func NewSealed(ctx context.Context, data []byte) (Sealed, error) {
	return sealedOut(newSealed(ctx, data))
}

// newSealed is [NewSealed] as a *sealedValue, for this package's own callers.
func newSealed(ctx context.Context, data []byte) (*sealedValue, error) {
	// First: every path below wipes data, and wiping a frozen view faults.
	if readOnly(data) {
		return nil, ErrSealSourceReadOnly
	}

	// The lookup below installs the default one-shot; an abandoned call must
	// not lock the configuration a later SetSealer is meant to make.
	if err := contextFailure[SealError](ctx, nil); err != nil {
		Wipe(data)
		return nil, err
	}

	s, err := processSealer()
	if err != nil {
		Wipe(data)
		return nil, err
	}
	return s.sealData(ctx, data)
}

// sealedOut hands v out as a [Sealed], keeping a failed seal a nil interface
// rather than one holding a nil *sealedValue.
func sealedOut(v *sealedValue, err error) (Sealed, error) {
	if v == nil {
		return nil, err
	}
	return v, err
}

// NewSealedFrom is [Sealer.SealFrom] under the process [Sealer]; src is left as it was.
func NewSealedFrom(ctx context.Context, src Handle) (Sealed, error) {
	return sealedOut(newSealedFrom(ctx, src))
}

// newSealedFrom is [NewSealedFrom] as a *sealedValue.
func newSealedFrom(ctx context.Context, src Handle) (*sealedValue, error) {
	if err := contextFailure[SealError](ctx, nil); err != nil {
		return nil, err
	}

	s, err := processSealer()
	if err != nil {
		return nil, err
	}
	return s.sealFromHandle(ctx, src)
}

// Open implements [Sealed.Open].
func (s *sealedValue) Open(ctx context.Context) (ByteAccess, error) {
	return byteAccess(s.openIn(ctx, newMemorySized))
}

// OpenIn implements [Sealed.OpenIn]. A typed-nil *budgetAllocator returns
// [ErrNilAllocator] and never falls back to an unbudgeted open; that check
// precedes the destroyed check.
func (s *sealedValue) OpenIn(ctx context.Context, b Backend) (Handle, error) {
	// First: a typed-nil *budgetAllocator is ErrNilAllocator, not ErrInvalidBackend.
	if a, ok := b.(*budgetAllocator); ok {
		m, err := s.openAdmitted(ctx, a)
		if err != nil {
			return nil, err
		}
		return m, nil
	}
	if isNilInterface(b) {
		return nil, ErrInvalidBackend
	}
	if _, ok := b.(lockedMemory); ok {
		m, err := s.Open(ctx)
		if err != nil {
			return nil, err
		}
		return m, nil
	}
	if t, ok := b.(regionTarget); ok {
		return s.openRegion(ctx, t)
	}
	imp, ok := b.(Importer)
	if !ok {
		return nil, &CapabilityError{Backend: b.Name(), Capability: CapabilityImport}
	}
	return s.openImported(ctx, imp)
}

// regionTarget is the capability, found by type assertion, of a backend whose
// handles are locked regions over its own pages: OpenIn decrypts straight into
// one, with no scratch enclave and no import. allocRegion returns a writable
// region of n bytes, admitted as the backend admits an import; regionHandle
// returns the opened, frozen region as the backend's handle. The secretmem
// backend has it; a backend without it is imported into as before.
type regionTarget interface {
	Backend
	allocRegion(n int) (*lockedRegion, error)
	regionHandle(r *lockedRegion) Handle
}

// openRegion is OpenIn into a regionTarget: the destination is t's region,
// and the plaintext is decrypted into its pages and nowhere else. t's own
// refusal of the destination is shaped as openImported shapes an import's.
func (s *sealedValue) openRegion(ctx context.Context, t regionTarget) (Handle, error) {
	r, err := s.openIn(ctx, func(n int) (*lockedRegion, error) {
		r, err := t.allocRegion(n)
		if err != nil {
			return nil, backendFailure[OpenError](err)
		}
		return r, nil
	})
	if err != nil {
		return nil, err
	}
	return t.regionHandle(r), nil
}

// openAdmitted is OpenIn into a, as a *lockedRegion.
func (s *sealedValue) openAdmitted(ctx context.Context, a *budgetAllocator) (*lockedRegion, error) {
	// A nil receiver keeps openIn's answer; a nil allocator is refused
	// whatever the value's state.
	if s != nil && a == nil {
		return nil, ErrNilAllocator
	}
	return s.openIn(ctx, a.admitSized)
}

// openImported is OpenIn into an importing backend other than locked memory.
func (s *sealedValue) openImported(ctx context.Context, imp Importer) (Handle, error) {
	if s == nil || s.sealedState == nil {
		return nil, ErrEnclaveDestroyed
	}

	sealer, blob, sealed, size, ok := s.pin()
	if !ok {
		return nil, ErrEnclaveDestroyed
	}
	defer s.unpin(sealer, blob, sealed)

	// Left writable, never frozen: the importer wipes it.
	scratch, err := sealer.open(ctx, s.version, blob, sealed, size, newMemorySized, false)
	if err != nil {
		return nil, err
	}
	var h Handle
	err = scratch.WithBytes(func(p []byte) error {
		var ierr error
		h, ierr = imp.Import(ctx, p, WithPurpose(PurposeMaterial))
		return ierr // Import wiped p on every path
	})
	// Its pages are already zero; a release the kernel refuses stays on the
	// WipeAll ledger.
	_ = scratch.Destroy()

	// A handle that refuses Destroy still holds the plaintext: the sealer
	// keeps it for its next Destroy to retry, and the CleanupError says so.
	if err != nil {
		if cerr := contextFailure[OpenError](ctx, err); cerr != nil {
			err = cerr
		} else {
			err = backendFailure[OpenError](err)
		}
		return nil, sealer.destroyOrRetain(err, h)
	}

	refused := &CapabilityError{Backend: imp.Name(), Capability: CapabilityBytes}
	if isNilInterface(h) {
		return nil, refused
	}
	if _, ok := h.(ByteAccess); !ok {
		return nil, sealer.destroyOrRetain(refused, h)
	}
	// The import ran after open's last check, and may have blocked: nothing
	// opened under a sealer destroyed meanwhile is returned.
	if err := sealer.usable(); err != nil {
		return nil, sealer.destroyOrRetain(err, h)
	}
	return h, nil
}

// openIn is the shared body of Open and openAdmitted; the value's lock is not held across Sealer.open.
func (s *sealedValue) openIn(ctx context.Context, dst func(int) (*lockedRegion, error)) (*lockedRegion, error) {
	if s == nil || s.sealedState == nil {
		return nil, ErrEnclaveDestroyed
	}

	sealer, blob, sealed, size, ok := s.pin()
	if !ok {
		return nil, ErrEnclaveDestroyed
	}
	defer s.unpin(sealer, blob, sealed)

	return sealer.open(ctx, s.version, blob, sealed, size, dst, true)
}

// pin registers an open in flight and returns the envelope it may read with
// the lock released, or ok false if the value is destroyed.
func (s *sealedValue) pin() (sealer *envelopeSealer, blob, sealed []byte, size int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed == nil {
		return nil, nil, nil, 0, false
	}
	s.opens++
	return s.sealer, s.blob, s.sealed, s.size, true
}

// unpin ends an open in flight. The last open out after a Destroy wipes the
// envelope halves Destroy left for it, and releases the value's hold on its
// sealer's KEK generation.
func (s *sealedValue) unpin(sealer *envelopeSealer, blob, sealed []byte) {
	s.mu.Lock()
	s.opens--
	last := s.opens == 0 && s.sealed == nil
	if last {
		Wipe(sealed)
	}
	s.mu.Unlock()

	if last {
		// Released before the wipe: the blob's header names the generation.
		sealer.releaseBlob(blob)
		Wipe(blob)
	}
}

// IsAlive implements [Sealed.IsAlive].
func (s *sealedValue) IsAlive() bool {
	if s == nil || s.sealedState == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sealed != nil
}

// Openable implements [Sealed.Openable]; a nil value returns
// [ErrEnclaveDestroyed].
func (s *sealedValue) Openable() error {
	if s == nil || s.sealedState == nil {
		return ErrEnclaveDestroyed
	}

	sealer, sealedAtGen, ok := s.openableSnapshot()
	if !ok {
		return ErrEnclaveDestroyed
	}
	return sealer.openable(sealedAtGen)
}

// openableSnapshot reads what Openable needs under the lock, reporting ok
// false for the destroyed state.
func (s *sealedValue) openableSnapshot() (*envelopeSealer, uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Destroy clears both together; testing the sealer too keeps ErrNilSealer
	// out of Openable's return set.
	if s.sealed == nil || s.sealer == nil {
		return nil, 0, false
	}
	return s.sealer, s.sealedAtGen, true
}

// Destroy implements [Sealed.Destroy]; it is safe on a nil value.
func (s *sealedValue) Destroy() error {
	if s == nil || s.sealedState == nil {
		return nil
	}

	s.mu.Lock()
	if s.sealed == nil {
		s.mu.Unlock()
		return nil
	}

	// With an open in flight the halves are still being read; unpin wipes
	// them, and releases the generation, when the last one finishes.
	sealer, blob := s.sealer, s.blob
	release := s.opens == 0
	if release {
		Wipe(s.sealed)
	}
	s.sealed = nil
	s.blob = nil
	s.size = 0
	s.sealer = nil
	s.mu.Unlock()

	if release {
		// In ModeRootKey the sealer retains the root-wrapped KEK this value
		// was sealed under until its last value is gone.
		sealer.releaseBlob(blob)
		Wipe(blob)
	}
	return nil
}

// String returns a redacted form, so an accidental %v or %s never prints the
// ciphertext.
func (s *sealedValue) String() string {
	return redacted("Sealed", s.IsAlive(), "sealed")
}

// GoString returns the same redacted form as String under %#v.
func (s *sealedValue) GoString() string {
	return redacted("Sealed", s.IsAlive(), "sealed")
}

// redacted is the form a value holding secret material prints as: its type
// and state, never its contents. live names the state of a value that is
// still alive.
func redacted(typeName string, alive bool, live string) string {
	if !alive {
		return typeName + "(destroyed)"
	}
	return typeName + "(" + live + ")"
}

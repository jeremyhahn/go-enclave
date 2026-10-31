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

// Sealed holds material encrypted at rest and decrypts it into a new
// memory enclave only when [Sealed.Open] is called. Use it for
// material needed occasionally and held for a long time; use a memory enclave
// ([NewMemory]) for material in continuous use.
//
// Each value is an envelope on the ordinary heap: the material sealed with
// AES-256-GCM under a fresh 32-byte data key (DEK), and the DEK wrapped by
// the [Sealer] (by its provider in [ModePerOperation], by its key hierarchy
// in [ModeRootKey]). The wrapped DEK is bound as additional authenticated
// data, so re-pairing halves from different values fails authentication.
//
// Recovered plaintext never reaches the ordinary heap, but AES key schedules
// do: every in-process AES operation leaves its key's expanded schedule on
// the heap, unerased unless the build has [KeyScheduleErasure], so a reader
// of this process's memory can recover the keys of recent seals and opens
// from it, and with them the values. This guarantee is weaker than the
// plaintext's, and what it exposes depends on the [Mode] the value was
// sealed under; see [Mode]. [WithRequireKeyScheduleErasure] refuses a sealer
// that would leave a schedule there.
//
// There is no constructor for sealed bytes: the envelope format is internal,
// unversioned and keyed to a process-lifetime Sealer.
//
// A Sealed owns no locked pages and is not destroyed by [WipeAll].
// After a sweep it may still report [Sealed.IsAlive] while
// [Sealed.Open] fails with [ErrSealerWiped]; [Sealed.Openable]
// reports which.
//
// Construct one with [NewSealed], [NewSealedFrom], [Sealer.Seal] or
// [Sealer.SealFrom]; the implementation is internal to this package. A Sealed
// is safe for concurrent use, and Destroy reaches every reference to it.
type Sealed interface {
	// Open decrypts the material directly into a new memory enclave and returns
	// it as a [ByteAccess]. The caller owns the result and must Destroy it;
	// each call returns an independent enclave. Open late and destroy early.
	//
	// The destination and the transient key pages are allocated outside any
	// [Allocator] budget; callers holding a budget, or opening into another
	// backend, use [Sealed.OpenIn].
	//
	// It returns ErrEnclaveDestroyed once Destroy has run, ErrSealedAuthentication
	// if the envelope does not authenticate, ErrLockedMemoryUnavailable when the
	// kernel refuses a locked page (the value survives and the open can be
	// retried), ErrSealerWiped when a shutdown sweep destroyed the sealer's keys,
	// and ErrSealerDestroyed after [Sealer.Destroy]. In [ModePerOperation] a
	// provider's own failure is joined under ErrOpenFailed. A failed open
	// returns a nil interface.
	//
	// ctx bounds the open. In [ModePerOperation] it is passed to the provider's
	// Unprotect; in [ModeRootKey] the open makes no provider call and ctx is
	// checked on entry only. An ended context fails the open with an error
	// matching both ErrOpenFailed and ctx.Err(), and not ErrSealedAuthentication
	// unless the provider reported that first (see [ErrOpenFailed]). The value is
	// left intact, and a destination recovered for an abandoned caller is
	// destroyed.
	Open(ctx context.Context) (ByteAccess, error)

	// OpenIn is [Sealed.Open] into b, any backend that can hold the material.
	//
	// For locked memory it decrypts in place, as Open does: [DefaultBackend] is
	// Open itself, and an [Allocator] from [NewAllocator] or
	// [NewAllocatorWithinRLimit] admits the destination against its budget, as
	// below. Into the secretmem backend ([NewSecretMemory]) it decrypts straight
	// into the returned handle's memfd_secret pages, admitted against that
	// backend's budget before anything is decrypted: the plaintext passes
	// through no scratch enclave, no import and no heap buffer, and a refusal of
	// those pages is the backend's failure, as an import's is below. Nothing
	// falls back to the scratch path. For any other backend that implements
	// [Importer] it decrypts into a locked scratch enclave and imports from it
	// with [PurposeMaterial]; the
	// importer wipes the scratch, which is then destroyed, so the plaintext never
	// reaches the heap. The caller owns the returned handle and must Destroy it.
	//
	// It returns [ErrInvalidBackend] for a nil or typed-nil b, a
	// [*CapabilityError] naming [CapabilityImport] for a backend that cannot
	// import, before anything is decrypted, and one naming [CapabilityBytes]
	// when the handle the backend returned has no [ByteAccess], which is
	// destroyed. These checks precede the destroyed check. A backend's own
	// failure is joined under [ErrOpenFailed], except [ErrInvalidImport] and the
	// capability refusals, which are returned as they are. Otherwise it returns
	// what Open returns.
	//
	// Into an Allocator, the destination is admitted against its budget,
	// reserved before any locked memory is requested and returned when the
	// caller destroys the result. Only the destination is admitted, in one
	// reservation taken first, so an open the budget refuses allocates nothing.
	// The transient DEK page (and, for a value under a retired [ModeRootKey]
	// generation, a KEK page) are not charged, so peak use can exceed the budget
	// by one page (two) per open in flight. A budget refusal, ErrBudgetExhausted
	// as a [BudgetError], leaves the value intact and is retryable. A context
	// already ended is refused before the reservation. Sealing is never
	// budgeted.
	OpenIn(ctx context.Context, b Backend) (Handle, error)

	// IsAlive reports whether this value still holds its ciphertext, that is,
	// whether [Sealed.Destroy] has not run. It does not mean the value can
	// be opened: after a shutdown [WipeAll] a value can report IsAlive while
	// [Sealed.Open] fails with [ErrSealerWiped]. Use
	// [Sealed.Openable] for that.
	IsAlive() bool

	// Openable reports whether [Sealed.Open] could still recover this
	// material, without recovering it. It returns nil if nothing known prevents
	// it, [ErrEnclaveDestroyed] if this value was destroyed,
	// [ErrSealerWiped] if a shutdown [WipeAll] destroyed in-process keys the
	// sealer needs, [ErrSealerDestroyed] after [Sealer.Destroy], and
	// [ErrOpenabilityUnknown] if a sweep has run since this value was sealed and
	// a [ModePerOperation] provider does not implement [HealthReporter]. A
	// provider's HealthReporter answer is believed.
	//
	// The answer is a snapshot for diagnostics, not a reservation, and nil is
	// narrower than "will succeed": it does not predict
	// [ErrSealedAuthentication], [ErrLockedMemoryUnavailable] or a device's own
	// failures. It takes no context and calls no provider other than
	// HealthReporter.Health, and holds no lock of this value's while consulting
	// the sealer.
	Openable() error

	// Destroy wipes the sealed material and releases it. It is idempotent.
	// Enclaves already returned by [Sealed.Open] are unaffected.
	//
	// It does not wait for opens in flight: they complete against the envelope
	// they pinned, the last one wipes it, and every Open starting afterwards
	// returns [ErrEnclaveDestroyed]. The error is always nil today; it matches
	// [Handle.Destroy] and [Sealer.Destroy].
	Destroy() error
}

// sealedValue is this package's [Sealed]. A nil *sealedValue is a valid
// receiver for every method. It must not be copied; its state sits behind one
// pointer, so even a copy is the same value, and destroying either destroys
// both.
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

// NewSealed encrypts data under the process [Sealer] and returns the sealed
// enclave. The process Sealer is whatever [SetSealer] installed, or, if
// nothing did before the first seal, a [SoftwareProvider] in [ModeRootKey].
// [Sealer.Seal] does the same for an explicit sealer.
//
// It takes ownership of data as [NewMemory] does: the caller's slice
// is wiped before it returns, on every path but one. Data this process cannot
// write, such as a view into a frozen memory enclave, cannot be wiped and is
// refused with [ErrSealSourceReadOnly] before anything else; seal such
// material with [NewSealedFrom].
//
// It returns ErrEmptyEnclave when data is empty, ErrMaterialTooLarge above
// AES-GCM's per-message ceiling, ErrSealFailed when the AEAD, the CSPRNG or
// the provider fails, ErrLockedMemoryUnavailable when the kernel refuses a
// locked page, ErrSealerWiped after a shutdown sweep destroyed the sealer's
// keys, and ErrSealerDestroyed after [Sealer.Destroy] on the process Sealer.
//
// ctx bounds every step that can block: the first root unseal in
// [ModeRootKey], and every Protect in [ModePerOperation]. An ended context
// fails the seal with an error matching both ErrSealFailed and ctx.Err(), with
// any underlying failure joined. A context already ended on entry is refused
// before the process Sealer is looked up, so it never installs the default.
// A root unsealed for a caller that then gave up is kept and used by the next
// seal.
//
// On a GOEXPERIMENT=boringcrypto build it always returns ErrSealFailed. A
// failed seal returns a nil interface.
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

// NewSealedFrom is [Sealer.SealFrom] under the process [Sealer], as
// [NewSealed] is [Sealer.Seal]: it seals the material src holds and leaves
// src as it was. A context already ended on entry is refused before the
// process Sealer is looked up.
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

// openIn is the shared body of Open and openAdmitted; dst makes the
// destination. The value's lock only pins and unpins the envelope and is
// not held across Sealer.open, which may block in a provider; Destroy takes
// no context and must not wait on that.
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

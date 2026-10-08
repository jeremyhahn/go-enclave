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

// SealedEnclave holds material encrypted at rest and decrypts it into a new
// [MemoryEnclave] only when [SealedEnclave.Open] is called. Use it for
// material needed occasionally and held for a long time; use a MemoryEnclave
// for material in continuous use.
//
// Each value is an envelope on the ordinary heap: the material sealed with
// AES-256-GCM under a fresh 32-byte data key (DEK), and the DEK wrapped by
// the [Sealer] (by its provider in [ModePerOperation], by its key hierarchy
// in [ModeRootKey]). The wrapped DEK is bound as additional authenticated
// data, so re-pairing halves from different values fails authentication.
//
// Recovered plaintext never reaches the ordinary heap, but AES key schedules
// do; what a reader of this process's memory can obtain depends on the
// [Mode] the value was sealed under. See [Mode] and [KeyScheduleErasure].
//
// There is no constructor for sealed bytes: the envelope format is internal,
// unversioned and keyed to a process-lifetime Sealer.
//
// A SealedEnclave owns no locked pages and is not destroyed by [WipeAll].
// After a sweep it may still report [SealedEnclave.IsAlive] while
// [SealedEnclave.Open] fails with [ErrSealerWiped]; [SealedEnclave.Openable]
// reports which.
//
// The zero value is not usable; construct one with [NewSealed] or
// [Sealer.Seal]. A nil *SealedEnclave is a valid receiver for every method.
// A SealedEnclave is safe for concurrent use.
type SealedEnclave struct {
	mu sync.RWMutex

	// sealer is nil'd on Destroy so a destroyed value does not pin a Sealer.
	sealer *Sealer

	// sealed is nonce || ciphertext || tag under the DEK; nil once destroyed.
	sealed []byte

	// blob is the wrapped DEK and the AAD sealed was bound to.
	blob []byte

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

// NewSealed encrypts data under the process [Sealer] and returns the sealed
// enclave. The process Sealer is whatever [SetSealer] installed, or, if
// nothing did before the first seal, a [SoftwareProvider] in [ModeRootKey].
// [Sealer.Seal] does the same for an explicit sealer.
//
// It takes ownership of data as [NewMemoryEnclave] does: the caller's slice
// is wiped before it returns, on every path.
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
// On a GOEXPERIMENT=boringcrypto build it always returns ErrSealFailed.
func NewSealed(ctx context.Context, data []byte) (*SealedEnclave, error) {
	// The lookup below installs the default one-shot; an abandoned call must
	// not lock the configuration a later SetSealer is meant to make.
	if err := contextFailure[sealFailed](ctx, nil); err != nil {
		Wipe(data)
		return nil, err
	}

	s, err := processSealer()
	if err != nil {
		Wipe(data)
		return nil, err
	}
	return s.Seal(ctx, data)
}

// Open decrypts the material directly into a new [MemoryEnclave] and returns
// it. The caller owns the result and must Destroy it; each call returns an
// independent enclave. Open late and destroy early.
//
// The destination and the transient key pages are allocated outside any
// [Allocator] budget; callers holding a budget use [SealedEnclave.OpenWith].
//
// It returns ErrEnclaveDestroyed once Destroy has run, ErrSealedAuthentication
// if the envelope does not authenticate, ErrLockedMemoryUnavailable when the
// kernel refuses a locked page (the value survives and the open can be
// retried), ErrSealerWiped when a shutdown sweep destroyed the sealer's keys,
// and ErrSealerDestroyed after [Sealer.Destroy]. In [ModePerOperation] a
// provider's own failure is joined under ErrOpenFailed.
//
// ctx bounds the open. In [ModePerOperation] it is passed to the provider's
// Unprotect; in [ModeRootKey] the open makes no provider call and ctx is
// checked on entry only. An ended context fails the open with an error
// matching both ErrOpenFailed and ctx.Err(), and not ErrSealedAuthentication
// unless the provider reported that first (see [ErrOpenFailed]). The value is
// left intact, and a destination recovered for an abandoned caller is
// destroyed.
func (s *SealedEnclave) Open(ctx context.Context) (*MemoryEnclave, error) {
	// nil is how the open path spells "unadmitted"; see allocSized.
	return s.openWith(ctx, nil)
}

// OpenWith is [SealedEnclave.Open] with the destination admitted against a's
// budget, reserved before any locked memory is requested and returned when
// the caller destroys the result. A nil a returns [ErrNilAllocator] and never
// falls back to an unbudgeted open; that check precedes the destroyed check.
//
// Only the destination is admitted, in one reservation taken first, so an
// open the budget refuses allocates nothing. The transient DEK page (and, for
// a value under a retired [ModeRootKey] generation, a KEK page) are not
// charged, so peak use can exceed the budget by one page (two) per open in
// flight.
//
// It returns everything Open returns, plus ErrNilAllocator and
// ErrBudgetExhausted (as a [BudgetError]). A budget refusal leaves the value
// intact and is retryable. A context already ended is refused before the
// reservation. Sealing is never budgeted.
func (s *SealedEnclave) OpenWith(ctx context.Context, a *Allocator) (*MemoryEnclave, error) {
	// A nil receiver keeps openWith's answer; a nil allocator is refused
	// whatever the value's state.
	if s != nil && a == nil {
		return nil, ErrNilAllocator
	}
	return s.openWith(ctx, a)
}

// openWith is the shared body of Open and OpenWith; a is nil for an
// unadmitted open. The value's lock only pins and unpins the envelope and is
// not held across Sealer.open, which may block in a provider; Destroy takes
// no context and must not wait on that.
func (s *SealedEnclave) openWith(ctx context.Context, a *Allocator) (*MemoryEnclave, error) {
	if s == nil {
		return nil, ErrEnclaveDestroyed
	}

	sealer, blob, sealed, size, ok := s.pin()
	if !ok {
		return nil, ErrEnclaveDestroyed
	}
	defer s.unpin(blob, sealed)

	return sealer.open(ctx, a, blob, sealed, size)
}

// pin registers an open in flight and returns the envelope it may read with
// the lock released, or ok false if the value is destroyed.
func (s *SealedEnclave) pin() (sealer *Sealer, blob, sealed []byte, size int, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed == nil {
		return nil, nil, nil, 0, false
	}
	s.opens++
	return s.sealer, s.blob, s.sealed, s.size, true
}

// unpin ends an open in flight. The last open out after a Destroy wipes the
// envelope halves Destroy left for it.
func (s *SealedEnclave) unpin(blob, sealed []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.opens--
	if s.opens == 0 && s.sealed == nil {
		Wipe(sealed)
		Wipe(blob)
	}
}

// IsAlive reports whether this value still holds its ciphertext, that is,
// whether [SealedEnclave.Destroy] has not run. It does not mean the value can
// be opened: after a shutdown [WipeAll] a value can report IsAlive while
// [SealedEnclave.Open] fails with [ErrSealerWiped]. Use
// [SealedEnclave.Openable] for that.
func (s *SealedEnclave) IsAlive() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sealed != nil
}

// Openable reports whether [SealedEnclave.Open] could still recover this
// material, without recovering it. It returns nil if nothing known prevents
// it, [ErrEnclaveDestroyed] if this value was destroyed (or is nil),
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
func (s *SealedEnclave) Openable() error {
	if s == nil {
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
func (s *SealedEnclave) openableSnapshot() (*Sealer, uint64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Destroy clears both together; testing the sealer too keeps ErrNilSealer
	// out of Openable's return set.
	if s.sealed == nil || s.sealer == nil {
		return nil, 0, false
	}
	return s.sealer, s.sealedAtGen, true
}

// Destroy wipes the sealed material and releases it. It is idempotent and
// safe on a nil enclave. Enclaves already returned by [SealedEnclave.Open]
// are unaffected.
//
// It does not wait for opens in flight: they complete against the envelope
// they pinned, the last one wipes it, and every Open starting afterwards
// returns [ErrEnclaveDestroyed]. The error is always nil today; it matches
// [MemoryEnclave.Destroy] and [Sealer.Destroy].
func (s *SealedEnclave) Destroy() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.sealed == nil {
		return nil
	}

	// With an open in flight the halves are still being read; unpin wipes
	// them when the last one finishes.
	if s.opens == 0 {
		Wipe(s.sealed)
		Wipe(s.blob)
	}
	s.sealed = nil
	s.blob = nil
	s.size = 0
	// In ModeRootKey the sealer also retains retired-generation blobs.
	s.sealer = nil
	return nil
}

// String returns a redacted form, so an accidental %v or %s never prints the
// ciphertext.
func (s *SealedEnclave) String() string {
	return redacted("SealedEnclave", s.IsAlive(), "sealed")
}

// GoString returns the same redacted form as String under %#v.
func (s *SealedEnclave) GoString() string {
	return redacted("SealedEnclave", s.IsAlive(), "sealed")
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

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

var (
	// ErrEmptyEnclave is returned when an enclave is requested for zero bytes
	// of material.
	ErrEmptyEnclave = errors.New("enclave: refusing to create an enclave over empty material")

	// ErrEnclaveDestroyed is returned when a destroyed enclave is opened or
	// read. The locked pages have already been wiped and released.
	ErrEnclaveDestroyed = errors.New("enclave: enclave has been destroyed")

	// ErrInvalidSize is returned by [NewMemoryEnclaveSized] and
	// [Allocator.NewSized], before anything is mapped, for a size that is
	// non-positive or too large to map (the sizes [LockedSize] reports as 0).
	ErrInvalidSize = errors.New("enclave: enclave size must be positive and small enough to map")

	// ErrLockedMemoryUnavailable reports that the kernel refused to map, lock,
	// protect or release an enclave's pages (often the RLIMIT_MEMLOCK ceiling).
	// Every [LockedMemoryError] matches it.
	ErrLockedMemoryUnavailable = errors.New("enclave: could not allocate locked memory")
)

// ErrReleasedWithoutWipe reports that an enclave's pages were unmapped without
// the in-process wipe because mprotect was denied (a seccomp filter, a
// sandbox). Nothing leaked: the pages were mlock'd throughout and the kernel
// zeroes them before reuse. An [UnwipedReleaseError] never also matches
// [ErrLockedMemoryUnavailable].
var ErrReleasedWithoutWipe = errors.New("enclave: pages unmapped without an in-process wipe; mprotect was denied")

// UnwipedReleaseError is the error behind [ErrReleasedWithoutWipe], which
// errors.Is reports for every UnwipedReleaseError.
type UnwipedReleaseError struct {
	// Cause is the refused mprotect's *os.SyscallError, deliberately not a
	// LockedMemoryError.
	Cause error
}

// Error implements error.
func (e *UnwipedReleaseError) Error() string {
	if e.Cause == nil {
		return ErrReleasedWithoutWipe.Error()
	}
	return ErrReleasedWithoutWipe.Error() + ": " + e.Cause.Error()
}

// Is reports every UnwipedReleaseError as ErrReleasedWithoutWipe.
func (e *UnwipedReleaseError) Is(target error) bool {
	return target == ErrReleasedWithoutWipe
}

// Unwrap returns the underlying mprotect failure so errors.As can reach it.
func (e *UnwipedReleaseError) Unwrap() error { return e.Cause }

// LockedMemoryError is the error behind [ErrLockedMemoryUnavailable], which
// errors.Is reports for every LockedMemoryError. Its Cause is diagnostic.
type LockedMemoryError struct {
	// Cause is the failing system call's error, or nil. It is typed any for
	// compatibility; every value this package sets is an error.
	Cause any
}

// Error implements error.
func (e *LockedMemoryError) Error() string {
	if e.Cause == nil {
		return ErrLockedMemoryUnavailable.Error()
	}
	return ErrLockedMemoryUnavailable.Error() + ": " + fmt.Sprint(e.Cause)
}

// Is reports every LockedMemoryError as ErrLockedMemoryUnavailable.
func (e *LockedMemoryError) Is(target error) bool {
	return target == ErrLockedMemoryUnavailable
}

// Unwrap returns the cause when it is an error, and nil otherwise.
func (e *LockedMemoryError) Unwrap() error {
	if err, ok := e.Cause.(error); ok {
		return err
	}
	return nil
}

// MemoryEnclave is a region of locked, guarded memory holding sensitive
// material. Construct one with [NewMemoryEnclave], [NewMemoryEnclaveCopy] or
// [NewMemoryEnclaveSized]. A nil *MemoryEnclave is a valid receiver: not
// alive, opens with [ErrEnclaveDestroyed], and Destroy returns nil.
//
// Every method except Open holds the enclave's lock for the whole access, so
// Destroy and Freeze wait out in-flight readers. Open's slice outlives the lock.
type MemoryEnclave struct {
	mu sync.RWMutex

	// holders counts goroutines holding or waiting for mu; the release that
	// takes it to zero wakes a waiting WipeAll. Every acquisition except the
	// sweep's TryLock must go through rlock or lock, or a wake-up is lost.
	holders atomic.Int32

	m *mapping

	// release, when non-nil, returns this enclave's Allocator reservation.
	release     func()
	releaseOnce sync.Once
}

// NewMemoryEnclave moves data into a new locked, read-only enclave. The
// caller's slice is wiped on every return path, including failure.
//
// It returns [ErrEmptyEnclave] for empty data and [ErrLockedMemoryUnavailable]
// when the kernel refuses the pages (also matching [ErrReleasedWithoutWipe] if
// the rollback had to unmap unwiped); a failure touches no other enclave. A
// concurrent [WipeAll] can make a successful return an already-destroyed
// enclave, so callers constructing during shutdown must check IsAlive.
func NewMemoryEnclave(data []byte) (*MemoryEnclave, error) {
	e, err := newMemoryEnclave(data)
	if err != nil {
		// Pages a refused rollback left mapped go to the orphan ledger.
		adoptOrphan(err, nil)
		return nil, err
	}
	return register(e), nil
}

// newMemoryEnclave builds the enclave without publishing it to the WipeAll
// ledger; the caller registers it as its last step.
func newMemoryEnclave(data []byte) (*MemoryEnclave, error) {
	defer wipe(data)
	return newMemoryEnclaveCopy(data)
}

// NewMemoryEnclaveCopy is [NewMemoryEnclave] without the wipe: src is left
// untouched on every path. Prefer NewMemoryEnclave; the src kept here is an
// unprotected heap copy the caller must [Wipe] when done. The result is frozen
// and the errors are NewMemoryEnclave's.
func NewMemoryEnclaveCopy(src []byte) (*MemoryEnclave, error) {
	e, err := newMemoryEnclaveCopy(src)
	if err != nil {
		adoptOrphan(err, nil) // see NewMemoryEnclave
		return nil, err
	}
	return register(e), nil
}

// newMemoryEnclaveCopy is the unpublished body both constructors share. It
// never writes src.
func newMemoryEnclaveCopy(src []byte) (*MemoryEnclave, error) {
	if len(src) == 0 {
		return nil, ErrEmptyEnclave
	}

	m, err := newMapping(len(src))
	if err != nil {
		return nil, err
	}

	copy(m.data, src)

	// A refused freeze leaves the region writable, so release can still wipe
	// it. A refused release hands the mapping out for the orphan ledger.
	if ferr := m.freeze(); ferr != nil {
		if rerr := m.release(); rerr != nil {
			var held *pagesHeldError
			if errors.As(rerr, &held) {
				held.orphan = m
			}
			return nil, errors.Join(ferr, rerr)
		}
		return nil, ferr
	}

	return &MemoryEnclave{m: m}, nil
}

// NewMemoryEnclaveSized returns an enclave over n zeroed, WRITABLE bytes, so
// generated material is produced in locked memory and never on the heap:
//
//	e, err := enclave.NewMemoryEnclaveSized(32)
//	if err != nil {
//	    return err
//	}
//	defer e.Destroy()
//	if err := e.WithBytes(func(key []byte) error {
//	    _, err := io.ReadFull(rand.Reader, key)
//	    return err
//	}); err != nil {
//	    return err
//	}
//	if err := e.Freeze(); err != nil { // a refused Freeze leaves it writable
//	    return err
//	}
//
// Until Freeze succeeds, finish the fill before sharing the enclave, and know
// that a retained slice silently corrupts the material instead of faulting.
// It returns [ErrInvalidSize] or [ErrLockedMemoryUnavailable], otherwise as
// [NewMemoryEnclave].
func NewMemoryEnclaveSized(n int) (*MemoryEnclave, error) {
	e, err := newMemoryEnclaveSized(n)
	if err != nil {
		adoptOrphan(err, nil) // see NewMemoryEnclave
		return nil, err
	}
	return register(e), nil
}

// newMemoryEnclaveSized is NewMemoryEnclaveSized without the publication step.
func newMemoryEnclaveSized(n int) (*MemoryEnclave, error) {
	if _, ok := lockedSize(int64(n)); !ok {
		return nil, ErrInvalidSize
	}

	m, err := newMapping(n)
	if err != nil {
		return nil, err
	}

	return &MemoryEnclave{m: m}, nil
}

// NewMemoryEnclaveFromString copies s into a new locked region.
//
// Deprecated: the source string cannot be wiped. Build the material as a
// []byte and use [NewMemoryEnclave], which wipes its input.
func NewMemoryEnclaveFromString(s string) (*MemoryEnclave, error) {
	return NewMemoryEnclave([]byte(s))
}

// withLocked runs fn against the material under the read lock.
func (e *MemoryEnclave) withLocked(fn func([]byte) error) error {
	if e == nil {
		return ErrEnclaveDestroyed
	}

	e.rlock()
	defer e.runlock()

	if e.m == nil || e.m.wiped {
		// Wiped but held for a retried release: destroyed, and its guard
		// pages are already read-write.
		return ErrEnclaveDestroyed
	}

	return fn(e.m.data)
}

// Open returns a slice aliasing the locked pages. It is UNSAFE: once Open
// returns no lock covers the slice, so a concurrent Destroy or [WipeAll] makes
// a later read fault the process.
//
// Deprecated: the returned slice is covered by no lock, and a concurrent
// Destroy or [WipeAll] faults a reader holding it. Use
// [MemoryEnclave.WithBytes], which holds the read lock for the whole borrow.
func (e *MemoryEnclave) Open() ([]byte, error) {
	if e == nil {
		return nil, ErrEnclaveDestroyed
	}

	e.rlock()
	defer e.runlock()

	if e.m == nil || e.m.wiped {
		return nil, ErrEnclaveDestroyed
	}

	return e.m.data, nil
}

// OpenString returns an unwipeable heap copy of the material, taken under the
// read lock, for APIs that only take strings.
//
// Deprecated: the returned string cannot be wiped and outlives the enclave.
// Use [MemoryEnclave.WithBytes] and pass the borrowed bytes on directly.
func (e *MemoryEnclave) OpenString() (string, error) {
	var s string
	if err := e.withLocked(func(b []byte) error {
		s = string(b)
		return nil
	}); err != nil {
		return "", err
	}
	return s, nil
}

// WithBytes calls fn with a view of the locked pages and returns fn's error,
// or [ErrEnclaveDestroyed]. The read lock is held across fn, so Destroy,
// Freeze and [WipeAll] wait for it. fn must not retain the view or call any
// method on the same enclave (deadlock); it may use other enclaves. A write
// through the view fills a sized enclave before Freeze and faults after.
func (e *MemoryEnclave) WithBytes(fn func([]byte) error) error {
	return e.withLocked(fn)
}

// Freeze makes the pages read-only so a stray write faults. It is idempotent
// and irreversible, and waits out in-flight borrows. It returns
// [ErrEnclaveDestroyed] for a destroyed enclave, and
// [ErrLockedMemoryUnavailable] if mprotect is refused, leaving the enclave
// alive and writable. A frozen enclave whose later unprotect is denied is
// released unwiped ([ErrReleasedWithoutWipe] from Destroy).
func (e *MemoryEnclave) Freeze() error {
	if e == nil {
		return ErrEnclaveDestroyed
	}

	// The write lock, so the protection change cannot land mid-fill.
	e.lock()
	defer e.unlock()

	// Re-protecting a wiped-but-held mapping would cost its retry an mprotect.
	if e.m == nil || e.m.wiped {
		return ErrEnclaveDestroyed
	}

	return e.m.freeze()
}

// Size reports the number of bytes held, or 0 once destroyed.
func (e *MemoryEnclave) Size() int {
	if e == nil {
		return 0
	}

	e.rlock()
	defer e.runlock()

	if e.m == nil || e.m.wiped {
		return 0
	}

	return len(e.m.data)
}

// IsAlive reports whether the locked region still holds material.
func (e *MemoryEnclave) IsAlive() bool {
	if e == nil {
		return false
	}

	e.rlock()
	defer e.runlock()

	return e.m != nil && !e.m.wiped
}

// EqualTo reports whether the enclave holds exactly other, or
// [ErrEnclaveDestroyed]. Its timing reveals whether the lengths differ but not
// the contents.
func (e *MemoryEnclave) EqualTo(other []byte) (bool, error) {
	equal := false
	if err := e.withLocked(func(b []byte) error {
		equal = subtle.ConstantTimeCompare(b, other) == 1
		return nil
	}); err != nil {
		return false, err
	}
	return equal, nil
}

// Destroy wipes the material, verifies the canary, and unlocks and unmaps the
// pages, waiting out in-flight borrows. It is idempotent, nil-safe and never
// panics. It returns nil, or:
//
//   - [ErrReleasedWithoutWipe]: mprotect was denied, the pages were unmapped
//     unwiped and are released.
//   - [ErrLockedMemoryUnavailable]: munlock or munmap was refused. The pages,
//     the [WipeAll] ledger entry and any [Allocator] reservation are kept;
//     Destroy again resumes. Once wiped, the enclave reads as destroyed.
//   - [ErrEnclaveCorrupted]: the canary or guards were overwritten. The pages
//     are still wiped and released; if the release was also refused the error
//     matches ErrLockedMemoryUnavailable too and the retry reports it again.
//
// Test ErrReleasedWithoutWipe first. A discarded error loses nothing: the next
// WipeAll retries held pages and reports every detected corruption.
func (e *MemoryEnclave) Destroy() error {
	if e == nil {
		return nil
	}

	err := e.releaseMapping()

	// Refund only once the pages are gone.
	if e.release != nil && releasedPages(err) {
		e.releaseOnce.Do(e.release)
	}

	// Before deregistering, so a sweep sees the ledger entry or the note.
	if errors.Is(err, ErrEnclaveCorrupted) {
		noteCorrupted(e)
	}

	if releasedPages(err) {
		deregister(e)
	}

	return err
}

// destroyTransient destroys a package-internal enclave whose release outcome
// must not change the operation's result; WipeAll keeps the report.
func destroyTransient(e *MemoryEnclave) {
	_ = e.Destroy()
}

// releasedPages reports whether err left the pages returned to the kernel. A
// pagesHeldError vetoes everything, since corruption joined with a refused
// release still matches ErrEnclaveCorrupted.
func releasedPages(err error) bool {
	if pagesHeld(err) {
		return false
	}
	return err == nil ||
		errors.Is(err, ErrEnclaveCorrupted) ||
		errors.Is(err, ErrReleasedWithoutWipe)
}

// pagesHeldError marks, transparently, a failure that left the pages mapped.
// locked says they are still mlock'd, so a failed constructor keeps its
// Allocator charge; orphan is the mapping a failed construction gives up.
type pagesHeldError struct {
	err    error
	locked bool
	orphan *mapping
}

// Error implements error, unchanged from the wrapped failure.
func (e *pagesHeldError) Error() string { return e.err.Error() }

// Unwrap returns the wrapped failure, so the sentinels it matches still match.
func (e *pagesHeldError) Unwrap() error { return e.err }

// pagesHeld reports whether err's tree holds a pagesHeldError.
func pagesHeld(err error) bool {
	var held *pagesHeldError
	return errors.As(err, &held)
}

// lockedPagesHeld reports whether err left pages that are still mlock'd.
func lockedPagesHeld(err error) bool {
	var held *pagesHeldError
	return errors.As(err, &held) && held.locked
}

// releaseMapping is the memory half of Destroy.
func (e *MemoryEnclave) releaseMapping() error {
	e.lock()
	defer e.unlock()
	return e.releaseLocked()
}

// rlock takes the read lock, counted in holders.
func (e *MemoryEnclave) rlock() {
	e.holders.Add(1)
	e.mu.RLock()
}

// runlock releases what rlock took.
func (e *MemoryEnclave) runlock() {
	e.mu.RUnlock()
	e.unhold()
}

// lock is rlock for the write lock: Freeze and Destroy.
func (e *MemoryEnclave) lock() {
	e.holders.Add(1)
	e.mu.Lock()
}

// unlock releases what lock took.
func (e *MemoryEnclave) unlock() {
	e.mu.Unlock()
	e.unhold()
}

// unhold decrements holders before reading sweepWaiting; reversing them loses
// wake-ups.
func (e *MemoryEnclave) unhold() {
	if e.holders.Add(-1) == 0 && sweepWaiting.Load() {
		wakeSweep()
	}
}

// tryOutcome is what tryReleaseMapping reports about the lock.
type tryOutcome uint8

const (
	// tryReleased: the lock was taken and a release attempted.
	tryReleased tryOutcome = iota
	// tryHeld: a holder will wake the sweep, so it may wait.
	tryHeld
	// tryContended: a spurious TryLock failure; retry, never wait.
	tryContended
)

// tryReleaseMapping is releaseMapping without waiting, for WipeAll only: a
// blocked Lock cannot be abandoned when ctx ends.
func (e *MemoryEnclave) tryReleaseMapping() (tryOutcome, error) {
	if !e.mu.TryLock() {
		// Read after the caller armed sweepWaiting.
		if e.holders.Load() != 0 {
			return tryHeld, nil
		}
		return tryContended, nil
	}
	defer e.mu.Unlock()
	return tryReleased, e.releaseLocked()
}

// releaseLocked is the body both release paths share. The caller holds e.mu.
func (e *MemoryEnclave) releaseLocked() error {
	if e.m == nil {
		return nil
	}

	err := e.m.release()
	// Drop the handle exactly when the pages are gone.
	if !releasedPages(err) {
		return err
	}
	e.m = nil
	return err
}

// String masks the contents.
func (e *MemoryEnclave) String() string {
	if !e.IsAlive() {
		return "MemoryEnclave(destroyed)"
	}
	return "MemoryEnclave(redacted)"
}

// GoString masks the contents under %#v.
func (e *MemoryEnclave) GoString() string {
	return e.String()
}

// Wipe overwrites b with zeroes. On heap memory it is best effort: the bytes
// may already have been swapped, dumped or copied by the runtime.
func Wipe(b []byte) {
	wipe(b)
}

// KeyScheduleErasure reports whether AES key schedules and HKDF temporaries
// are erased after use. It is true only with GOEXPERIMENT=runtimesecret on
// linux/amd64 or linux/arm64 (not Android), where they run under
// runtime/secret.Do; elsewhere they stay on the heap until reused.
func KeyScheduleErasure() bool { return keyScheduleErasure }

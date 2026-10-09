// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"errors"
	"sync"
	"sync/atomic"
)

// MemoryEnclave is a region of locked, guarded memory holding sensitive
// material. Construct one with [NewMemoryEnclave], [NewMemoryEnclaveCopy] or
// [NewMemoryEnclaveSized]. A nil *MemoryEnclave is a valid receiver: not
// alive, borrows fail with [ErrEnclaveDestroyed], and Destroy returns nil.
//
// Every method holds the enclave's lock for the whole access, so Destroy and
// Freeze wait out in-flight borrows.
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
	defer Wipe(data)
	if len(data) == 0 {
		return nil, ErrEmptyEnclave
	}
	m, err := newFrozenCopy(data)
	return publish(m, err, nil)
}

// NewMemoryEnclaveCopy is [NewMemoryEnclave] without the wipe: src is left
// untouched on every path. Prefer NewMemoryEnclave; the src kept here is an
// unprotected heap copy the caller must [Wipe] when done. The result is frozen
// and the errors are NewMemoryEnclave's.
func NewMemoryEnclaveCopy(src []byte) (*MemoryEnclave, error) {
	if len(src) == 0 {
		return nil, ErrEmptyEnclave
	}
	m, err := newFrozenCopy(src)
	return publish(m, err, nil)
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
	// newMapping is the size check: it refuses n with ErrInvalidSize.
	m, err := newMapping(n)
	return publish(m, err, nil)
}

// newFrozenCopy maps len(src) bytes, copies src in and freezes them. It never
// writes src, and trusts its caller to have refused an empty src.
func newFrozenCopy(src []byte) (*mapping, error) {
	m, err := newMapping(len(src))
	if err != nil {
		return nil, err
	}
	return m.loadFrozen(src)
}

// loadFrozen copies src into m and freezes it, releasing m if it cannot.
func (m *mapping) loadFrozen(src []byte) (*mapping, error) {
	copy(m.data, src)

	// A refused freeze leaves the region writable, so release can still wipe
	// it. A refused release hands the mapping out for the orphan ledger.
	if ferr := m.freeze(); ferr != nil {
		if rerr := m.release(); rerr != nil {
			var held *pagesHeldError
			if errors.As(rerr, &held) {
				held.orphan = m
			}
			return nil, withCleanupFailure(ferr, rerr)
		}
		return nil, ferr
	}

	return m, nil
}

// publish is the last step of every constructor, admitted or not. On success
// it registers m as an enclave whose release runs once its pages go back. On
// failure it hands any pages err left mapped to the orphan ledger with
// release, so release must be nil unless those pages are still locked: an
// admitted caller refunds a charge nothing holds itself, at once.
func publish(m *mapping, err error, release func()) (*MemoryEnclave, error) {
	if err != nil {
		adoptOrphan(err, release)
		return nil, err
	}
	// register publishes the enclave to a concurrent WipeAll, so release is set
	// first: otherwise a sweep could unmap the pages while the budget kept the
	// charge.
	return register(&MemoryEnclave{m: m, release: release}), nil
}

// WithBytes calls fn with a view of the locked pages and returns fn's error,
// or [ErrEnclaveDestroyed]. The read lock is held across fn, so Destroy,
// Freeze and [WipeAll] wait for it. fn must not retain the view or call any
// method on the same enclave (deadlock); it may use other enclaves. A write
// through the view fills a sized enclave before Freeze and faults after.
func (e *MemoryEnclave) WithBytes(fn func([]byte) error) error {
	if e == nil {
		return ErrEnclaveDestroyed
	}

	e.rlock()
	defer e.runlock()

	if !e.holdsMaterial() {
		return ErrEnclaveDestroyed
	}

	return fn(e.m.data)
}

// holdsMaterial reports whether the material is still there. It is false once
// the pages are released, and once they are wiped but held for a retried
// release, whose guard pages are already read-write. The caller holds e.mu.
func (e *MemoryEnclave) holdsMaterial() bool {
	return e.m != nil && !e.m.wiped
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
	if !e.holdsMaterial() {
		return ErrEnclaveDestroyed
	}

	return e.m.freeze()
}

// Size reports the number of bytes held, or 0 once destroyed.
func (e *MemoryEnclave) Size() int {
	n := 0
	_ = e.WithBytes(func(b []byte) error {
		n = len(b)
		return nil
	})
	return n
}

// IsAlive reports whether the locked region still holds material.
func (e *MemoryEnclave) IsAlive() bool {
	return e.WithBytes(func([]byte) error { return nil }) == nil
}

// EqualTo reports whether the enclave holds exactly other, or
// [ErrEnclaveDestroyed]. Its timing reveals whether the lengths differ but not
// the contents.
func (e *MemoryEnclave) EqualTo(other []byte) (bool, error) {
	equal := false
	if err := e.WithBytes(func(b []byte) error {
		equal = equalConstantTime(b, other)
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

	e.lock()
	err := e.releaseLocked()
	e.unlock()

	settleRelease(e, err)
	return err
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

// releaseLocked is the memory half of every release: Destroy's and the
// sweep's. The caller holds e.mu, or is the sweep releasing an orphan no one
// else can reach.
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

// Backend returns the locked-memory backend, [DefaultBackend], which made
// every MemoryEnclave. It is nil-safe, and the same once destroyed.
func (e *MemoryEnclave) Backend() Backend { return lockedMemory{} }

// KeyScheduleErasure reports whether AES key schedules and HKDF temporaries
// are erased after use. It is true only with GOEXPERIMENT=runtimesecret on
// linux/amd64 or linux/arm64 (not Android), where they run under
// runtime/secret.Do; elsewhere they stay on the heap until reused.
func KeyScheduleErasure() bool { return keyScheduleErasure }

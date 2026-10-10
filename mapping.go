// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"crypto/rand"
	"errors"
	"math"
	"os"
)

// Fault-injection seams: each is one system call or construction step with no
// side effects of its own, reassigned only by this package's tests.
var (
	lockMemory      = sysLock
	unlockMemory    = sysUnlock
	protectMemory   = sysProtect
	unmapMemory     = sysUnmap
	excludeCoreDump = excludeFromCoreDump
	excludeFork     = excludeFromFork
	fillCanary      = randomCanary
)

// randomCanary fills b from crypto/rand.
func randomCanary(b []byte) error {
	_, err := rand.Read(b)
	return err
}

// pageSize is the mapping granularity and the RLIMIT_MEMLOCK accounting unit.
var pageSize = int64(os.Getpagesize())

// maxInt is the largest int, the ceiling a whole mapping has to fit under.
const maxInt = int64(^uint(0) >> 1)

// LockedSize reports the locked memory an n-byte enclave consumes (n rounded
// up to a page, guard pages excluded), for sizing an [Allocator] budget:
// NewAllocator(100 * LockedSize(32)). It returns 0 for an impossible size.
func LockedSize(n int) int64 {
	locked, ok := lockedSize(int64(n))
	if !ok {
		return 0
	}
	return locked
}

// lockedSize returns n rounded up to a whole page and whether a mapping of
// that size plus two guard pages fits in an int. It divides before multiplying
// because n+pageSize-1 can overflow and wrap negative.
func lockedSize(n int64) (int64, bool) {
	if n <= 0 {
		return 0, false
	}
	pages := (n-1)/pageSize + 1
	if pages > math.MaxInt64/pageSize {
		return 0, false
	}
	locked := pages * pageSize
	if locked > maxInt-2*pageSize {
		return 0, false
	}
	return locked, true
}

// mapping is one guarded, locked allocation, not safe for concurrent use:
//
//	| preguard | canary … data | postguard |
//	|<- page ->|<-- innerLen ->|<- page  ->|
//
// Both guard pages hold a copy of the canary. The canary is empty when the
// size is a page multiple.
type mapping struct {
	// memory is the whole allocation. Every other field is a sub-slice of it.
	memory []byte
	// data is the caller-visible region.
	data []byte
	// inner is the mlock'd region: canary plus data, a whole number of pages.
	inner []byte
	// preguard and postguard are the inaccessible pages either side of inner.
	preguard  []byte
	postguard []byte
	// canary is the slack ahead of data, verified on release.
	canary []byte
	// mutable records whether inner is writable.
	mutable bool
	// corrupted is sticky until the pages are gone: the check that sets it
	// wipes the canary and guards, so it cannot be repeated on a retry.
	corrupted bool
	// verified records that the check ran and the mapping was wiped.
	verified bool
	// wiped records that the material is gone while the pages are still held.
	wiped bool
	// unlocked records that inner is not mlock'd. A retry must not unlock
	// again: Windows' VirtualUnlock refuses unlocked pages (ERROR_NOT_LOCKED).
	unlocked bool
	// abandoned marks an empty mapping a failed construction gave up.
	abandoned bool
}

// newMapping maps, locks and guards a zeroed, mutable region for size bytes.
// Every failure returns a LockedMemoryError and rolls back what it took.
func newMapping(size int) (*mapping, error) {
	innerLen, ok := lockedSize(int64(size))
	if !ok {
		return nil, ErrInvalidSize
	}
	return mapLocked(size, innerLen)
}

// mapLocked is newMapping for a caller that has already rounded size up to
// innerLen with lockedSize, as the allocator does to charge its budget.
func mapLocked(size int, innerLen int64) (*mapping, error) {
	total := int(innerLen) + 2*int(pageSize)

	// Anonymous pages arrive zero-filled.
	memory, err := sysMap(total)
	if err != nil {
		return nil, &LockedMemoryError{Cause: err}
	}

	page := int(pageSize)
	inner := memory[page : page+int(innerLen) : page+int(innerLen)]
	m := &mapping{
		memory:    memory,
		inner:     inner,
		preguard:  memory[0:page:page],
		postguard: memory[page+int(innerLen) : total : total],
		// data ends inner, so the byte after it is the postguard.
		data:    inner[len(inner)-size : len(inner) : len(inner)],
		canary:  inner[0 : len(inner)-size : len(inner)-size],
		mutable: true,
	}

	locked := false
	// Lock before anything sensitive is written.
	if err := lockMemory(m.inner); err != nil {
		return nil, m.abandon(err, locked)
	}
	locked = true

	if err := excludeCoreDump(m.inner); err != nil {
		return nil, m.abandon(err, locked)
	}

	if err := excludeFork(m.memory); err != nil {
		return nil, m.abandon(err, locked)
	}

	// Random, so an overflow cannot reproduce it with a predictable pattern.
	if err := fillCanary(m.canary); err != nil {
		return nil, m.abandon(err, locked)
	}

	copyConstantTime(m.preguard, m.canary)
	copyConstantTime(m.postguard, m.canary)

	if err := protectMemory(m.preguard, protNoAccess); err != nil {
		return nil, m.abandon(err, locked)
	}
	if err := protectMemory(m.postguard, protNoAccess); err != nil {
		return nil, m.abandon(err, locked)
	}

	return m, nil
}

// abandon rolls back an empty, partially built mapping and returns cause with
// any cleanup failure. A refused munlock still goes on to munmap, which drops
// the lock. If munmap is refused, the mapping is handed out in a
// pagesHeldError, marked verified so its half-built canary is never checked.
func (m *mapping) abandon(cause error, locked bool) error {
	failure := error(&LockedMemoryError{Cause: cause})

	var cleanup error
	m.unlocked = !locked
	if !m.unlocked {
		if err := unlockMemory(m.inner); err != nil {
			cleanup = err
		} else {
			m.unlocked = true
		}
	}
	mapped := false
	if err := unmapMemory(m.memory); err != nil {
		cleanup = withCleanupFailure(cleanup, err)
		mapped = true
	}
	if cleanup == nil {
		return failure
	}

	report := withCleanupFailure(failure, &LockedMemoryError{Cause: cleanup})
	if !mapped {
		// Unmapped, so nothing is held, a refused munlock included.
		return report
	}
	m.verified, m.wiped, m.abandoned = true, true, true
	return &pagesHeldError{err: report, locked: !m.unlocked, orphan: m}
}

// freeze makes the data region read-only, so a write through a retained slice
// faults instead of silently corrupting the material. It is idempotent.
func (m *mapping) freeze() error {
	if !m.mutable {
		return nil
	}
	if err := protectMemory(m.inner, protReadOnly); err != nil {
		return &LockedMemoryError{Cause: err}
	}
	m.mutable = false
	return nil
}

// wipeAndVerify zeroes the whole mapping, then checks the canary and guards.
// The check runs at most once; a retry returns the first result. It returns
// ErrEnclaveCorrupted, or the refused mprotect's own error for release to
// classify.
func (m *mapping) wipeAndVerify() error {
	if m.verified {
		if m.corrupted {
			return ErrEnclaveCorrupted
		}
		return nil
	}

	// Wipe a writable data region first, with no syscall that can be denied,
	// so a refused mprotect below cannot leave an unfrozen enclave's material
	// behind. Only the data: the canary is still needed for the check.
	if m.mutable {
		Wipe(m.data)
		m.wiped = true
	}

	// The guards are PROT_NONE and a frozen inner is read-only. A refusal is
	// handled by release.
	if err := protectMemory(m.memory, protReadWrite); err != nil {
		return err
	}
	m.mutable = true

	Wipe(m.data)

	// OR'd in, never assigned: corrupted is sticky.
	m.corrupted = m.corrupted ||
		!equalConstantTime(m.preguard, m.postguard) ||
		!equalConstantTime(m.preguard[:len(m.canary)], m.canary)

	Wipe(m.memory)

	// Set before the error return: the guards and canary are now zero, so the
	// check cannot be redone if a later step fails.
	m.wiped = true
	m.verified = true

	if m.corrupted {
		return ErrEnclaveCorrupted
	}
	return nil
}

// release wipes and verifies, munlocks (at most once) and munmaps. A refused
// munlock or munmap keeps the mapping intact behind a pagesHeldError so a
// retry resumes; a refused mprotect unmaps anyway, as an UnwipedReleaseError
// unless the data was already wiped.
func (m *mapping) release() error {
	// Step 1. Corruption falls through and is reported once the pages are
	// gone; any other error is the refused mprotect.
	if err := m.wipeAndVerify(); err != nil && !errors.Is(err, ErrEnclaveCorrupted) {
		// A frozen region cannot be wiped without the denied mprotect, and
		// under a permanent denial (seccomp) keeping it would leave the
		// material resident for the process lifetime. Unmap it unwiped: it
		// was mlock'd throughout and the kernel zeroes anonymous pages before
		// reuse. No munlock first; munmap drops the lock.
		if uerr := unmapMemory(m.memory); uerr != nil {
			// Refused too: keep everything for a retry.
			return &pagesHeldError{
				err:    withCleanupFailure(&LockedMemoryError{Cause: err}, uerr),
				locked: !m.unlocked,
			}
		}

		wiped := m.wiped
		m.forget()
		if wiped {
			// A writable region was wiped before the refusal: the material
			// is gone and so are the pages. Only the canary check was
			// skipped, and the canary holds no material.
			return nil
		}
		// The raw OS error, not a LockedMemoryError, so this matches only
		// ErrReleasedWithoutWipe and never reads as "pages still held".
		return &UnwipedReleaseError{Cause: err}
	}

	// Step 2. An enclave stops at a refused unlock; an abandoned mapping goes
	// on to the munmap, which drops the lock, rather than strand a locked
	// orphan while munlock stays refused.
	var unlockErr error
	if !m.unlocked {
		if err := unlockMemory(m.inner); err != nil {
			if !m.abandoned {
				return m.held(&LockedMemoryError{Cause: err})
			}
			unlockErr = err
		} else {
			m.unlocked = true
		}
	}

	// Step 3.
	if err := unmapMemory(m.memory); err != nil {
		return m.held(&LockedMemoryError{Cause: withCleanupFailure(unlockErr, err)})
	}

	// The pages are gone: the only place the sticky flags may be cleared.
	corrupted := m.corrupted
	m.forget()

	if corrupted {
		return ErrEnclaveCorrupted
	}
	return nil
}

// forget clears the mapping; call it only after a successful unmap.
func (m *mapping) forget() {
	m.memory, m.data, m.inner = nil, nil, nil
	m.preguard, m.postguard, m.canary = nil, nil, nil
	m.mutable, m.corrupted, m.verified, m.unlocked = false, false, false, false
	m.wiped, m.abandoned = false, false
}

// held wraps a refused unlock or unmap as a pagesHeldError, reported with any
// corruption already detected.
func (m *mapping) held(err error) error {
	if m.corrupted {
		err = withCleanupFailure(ErrEnclaveCorrupted, err)
	}
	return &pagesHeldError{err: err, locked: !m.unlocked}
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"bytes"
	"crypto/rand"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMemoryEnclave_AllocateInsideBorrow pins that allocating, borrowing and
// destroying a second enclave inside a live borrow of the first does not block:
// allocation and borrows share no lock.
//
// The wait is bounded around the call so a deadlock fails with a named reason
// instead of the suite timeout.
func TestMemoryEnclave_AllocateInsideBorrow(t *testing.T) {
	const outerMaterial = "outer-private-key-material"

	outer, err := NewMemoryEnclave([]byte(outerMaterial))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}

	// Conditional: Destroy waits on the borrow, so an unconditional deferred
	// Destroy would hang on the very deadlock this test reports.
	completed := false
	defer func() {
		if completed {
			outer.Destroy()
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- outer.WithBytes(func(b []byte) error {
			// Everything below runs while the outer borrow is live.
			inner, ierr := NewMemoryEnclaveSized(32)
			if ierr != nil {
				return ierr
			}
			if ierr := inner.WithBytes(func(key []byte) error {
				_, rerr := io.ReadFull(rand.Reader, key)
				return rerr
			}); ierr != nil {
				inner.Destroy()
				return ierr
			}
			inner.Destroy()

			if !bytes.Equal(b, []byte(outerMaterial)) {
				return errors.New("outer material changed underneath the borrow")
			}
			return nil
		})
	}()

	select {
	case err := <-done:
		completed = true
		if err != nil {
			t.Fatalf("borrow: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("allocating inside a live borrow did not complete within 30s: " +
			"allocation and borrows are serialized against each other again")
	}
}

// TestMemoryEnclave_ConcurrentAllocationDuringBorrows is the same property under
// load: many goroutines allocate and destroy an enclave inside borrows of a
// shared one. The work is a fixed iteration count; the only clock bounds the wait.
func TestMemoryEnclave_ConcurrentAllocationDuringBorrows(t *testing.T) {
	const (
		material   = "shared-key-material"
		goroutines = 8
		iterations = 200
	)

	held, err := NewMemoryEnclave([]byte(material))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	// Conditional for the reason TestMemoryEnclave_AllocateInsideBorrow gives.
	drained := false
	defer func() {
		if drained {
			held.Destroy()
		}
	}()

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if err := held.WithBytes(func(b []byte) error {
					e, aerr := NewMemoryEnclaveSized(64)
					if aerr != nil {
						return aerr
					}
					e.Destroy()
					if !bytes.Equal(b, []byte(material)) {
						return errors.New("material changed underneath the borrow")
					}
					return nil
				}); err != nil {
					t.Errorf("borrow: %v", err)
					return
				}
			}
		}()
	}

	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()

	select {
	case <-finished:
		drained = true
	case <-time.After(60 * time.Second):
		t.Fatalf("%d goroutines x %d borrow-and-allocate iterations did not finish within 60s; "+
			"allocation and borrows are serialized against each other again",
			goroutines, iterations)
	}
}

// TestMapping_WipesBeforeRelease asserts the whole mapping, guards and canary
// included, is zero after wipeAndVerify and before the pages go back to the kernel.
func TestMapping_WipesBeforeRelease(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	copy(m.data, bytes.Repeat([]byte{0xA5}, 64))

	// Taken first: release nils the fields.
	memory, inner := m.memory, m.inner

	if err := m.wipeAndVerify(); err != nil {
		t.Fatalf("wipeAndVerify: %v", err)
	}
	for i, c := range memory {
		if c != 0 {
			t.Fatalf("byte %d of the mapping = %#x after the wipe, want 0", i, c)
		}
	}

	if err := sysUnlock(inner); err != nil {
		t.Errorf("munlock: %v", err)
	}
	if err := sysUnmap(memory); err != nil {
		t.Errorf("munmap: %v", err)
	}
}

// TestMapping_CanaryDetectsUnderflow pins that a write into the slack ahead of the
// data (an underflow, which no guard page catches) is reported as
// ErrEnclaveCorrupted, and that the mapping is released anyway.
func TestMapping_CanaryDetectsUnderflow(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	if len(m.canary) == 0 {
		t.Fatal("a 32-byte mapping has no canary slack; the layout changed and this test is vacuous")
	}

	// An underflow: write into the slack immediately ahead of the data.
	m.canary[len(m.canary)-1] ^= 0xFF

	err = m.release()
	if !errors.Is(err, ErrEnclaveCorrupted) {
		t.Errorf("release after an underflow = %v, want ErrEnclaveCorrupted", err)
	}
	if m.memory != nil {
		t.Error("the mapping was not released after a detected corruption")
	}
}

// TestMapping_CanaryVerifiesOnACleanRelease is the negative control: an untouched
// mapping releases without a corruption report.
func TestMapping_CanaryVerifiesOnACleanRelease(t *testing.T) {
	for _, size := range []int{1, 32, 4095, 4096, 8192} {
		m, err := newMapping(size)
		if err != nil {
			t.Fatalf("newMapping(%d): %v", size, err)
		}
		copy(m.data, bytes.Repeat([]byte{0x5A}, size))
		if err := m.release(); err != nil {
			t.Errorf("release of a clean %d-byte mapping = %v, want nil", size, err)
		}
	}
}

// TestMapping_LayoutInvariants pins the geometry the guard pages and canary rely
// on, chiefly that the data ends flush against the postguard.
func TestMapping_LayoutInvariants(t *testing.T) {
	page := int(pageSize)
	for _, size := range []int{1, 32, page - 1, page, page + 1, 3*page - 7} {
		m, err := newMapping(size)
		if err != nil {
			t.Fatalf("newMapping(%d): %v", size, err)
		}

		innerLen := int(LockedSize(size))
		if len(m.memory) != innerLen+2*page {
			t.Errorf("size %d: mapping is %d bytes, want %d", size, len(m.memory), innerLen+2*page)
		}
		if len(m.inner) != innerLen {
			t.Errorf("size %d: inner is %d bytes, want %d", size, len(m.inner), innerLen)
		}
		if len(m.data) != size {
			t.Errorf("size %d: data is %d bytes", size, len(m.data))
		}
		if len(m.preguard) != page || len(m.postguard) != page {
			t.Errorf("size %d: guards are %d/%d bytes, want %d each", size, len(m.preguard), len(m.postguard), page)
		}
		if len(m.canary) != innerLen-size {
			t.Errorf("size %d: canary is %d bytes, want %d", size, len(m.canary), innerLen-size)
		}
		// Data ends flush with the locked region, so an overflow faults.
		if &m.inner[len(m.inner)-1] != &m.data[len(m.data)-1] {
			t.Errorf("size %d: data does not end flush with the locked region", size)
		}
		// Fresh pages arrive zeroed, so an all-zero canary means it was
		// never randomized.
		if len(m.canary) >= 8 {
			zero := true
			for _, c := range m.canary {
				if c != 0 {
					zero = false
					break
				}
			}
			if zero {
				t.Errorf("size %d: canary is all zeroes; it was never randomized", size)
			}
		}

		for i, c := range m.data {
			if c != 0 {
				t.Fatalf("size %d: data[%d] = %#x on a fresh mapping, want 0", size, i, c)
			}
		}

		if err := m.release(); err != nil {
			t.Errorf("size %d: release: %v", size, err)
		}
	}
}

// TestPackageDoesNotImportMemguard asserts no package file and no go.mod entry
// pulls in memguard, whose process-global registry would make these pages
// purgeable. Behavior cannot show this; only the import graph can.
func TestPackageDoesNotImportMemguard(t *testing.T) {
	const forbidden = "github.com/awnumar/memguard"

	// File by file rather than parser.ParseDir, which is deprecated and would
	// skip files excluded by build tags on this platform.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading the package directory: %v", err)
	}

	fset := token.NewFileSet()
	files := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		files++
		for _, imp := range file.Imports {
			if strings.Contains(imp.Path.Value, forbidden) {
				t.Errorf("%s imports %s; go-enclave's pages would rejoin memguard's "+
					"global registry and become purgeable again", name, forbidden)
			}
		}
	}
	if files < 2 {
		t.Fatalf("only %d Go files parsed; the test would be vacuous", files)
	}

	// An indirect requirement in go.mod means something still links it.
	mod, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}
	if strings.Contains(string(mod), forbidden) {
		t.Errorf("go.mod still requires %s", forbidden)
	}
}

// TestMapping_FreezeIsIdempotent pins that a second freeze is a no-op and that a
// frozen mapping still releases cleanly.
func TestMapping_FreezeIsIdempotent(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	if !m.mutable {
		t.Error("a fresh mapping is not mutable; the fill path would fault")
	}
	if err := m.freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if m.mutable {
		t.Error("still mutable after freeze")
	}
	if err := m.freeze(); err != nil {
		t.Fatalf("second freeze: %v", err)
	}

	if err := m.release(); err != nil {
		t.Errorf("release of a frozen mapping: %v", err)
	}
}

// TestMapping_FrozenRegionIsStillWiped pins that a frozen mapping is melted and
// fully zeroed by wipeAndVerify. The refused-mprotect path for a frozen enclave is
// covered by TestMemoryEnclave_FrozenDestroyFallsBackToUnmap.
func TestMapping_FrozenRegionIsStillWiped(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	copy(m.data, bytes.Repeat([]byte{0xA5}, 64))

	if err := m.freeze(); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if m.mutable {
		t.Fatal("the mapping is still writable after freeze; this test would be measuring the unfrozen path")
	}

	// Taken first: release nils the fields.
	memory, inner := m.memory, m.inner

	if err := m.wipeAndVerify(); err != nil {
		t.Fatalf("wipeAndVerify on a frozen mapping: %v", err)
	}
	if !m.mutable {
		t.Error("a frozen mapping was not recorded as melted; release would then skip the melt on a retry " +
			"and wipe a read-only region")
	}
	for i, c := range memory {
		if c != 0 {
			t.Fatalf("byte %d of a frozen mapping = %#x after the wipe, want 0", i, c)
		}
	}

	if err := sysUnlock(inner); err != nil {
		t.Errorf("munlock: %v", err)
	}
	if err := sysUnmap(memory); err != nil {
		t.Errorf("munmap: %v", err)
	}
}

// TestMapping_RejectsUnmappableSizes pins that newMapping itself returns
// ErrInvalidSize for a size it cannot lay out.
func TestMapping_RejectsUnmappableSizes(t *testing.T) {
	maxIntV := int(^uint(0) >> 1)
	for _, n := range []int{0, -1, -4096, maxIntV, maxIntV - int(pageSize)} {
		m, err := newMapping(n)
		if !errors.Is(err, ErrInvalidSize) {
			t.Errorf("newMapping(%d) = %v, want ErrInvalidSize", n, err)
		}
		if m != nil {
			t.Errorf("newMapping(%d) returned a non-nil mapping", n)
			_ = m.release()
		}
	}
}

// TestMapping_ReleaseKeepsStateWhenUnmapFails pins that a release the kernel
// refuses keeps every field of the mapping, reports the pages as held, and that a
// retry then completes.
func TestMapping_ReleaseKeepsStateWhenUnmapFails(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	lift := denyProtectAndUnmap(t)
	err = m.release()

	if err == nil {
		t.Fatal("release reported success on a region it could not protect")
	}
	if !pagesHeld(err) {
		t.Errorf("pagesHeld(%v) = false, want true: nothing could return the pages", err)
	}
	if errors.Is(err, ErrEnclaveCorrupted) {
		t.Errorf("err = %v, want a mapping failure rather than a canary report", err)
	}
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Errorf("err = %v, want ErrLockedMemoryUnavailable", err)
	}

	if m.memory == nil || m.inner == nil || m.data == nil ||
		m.preguard == nil || m.postguard == nil {
		t.Fatal("release discarded the mapping it could not unmap; the pages are now unreachable")
	}

	lift()
	if err := m.release(); err != nil {
		t.Errorf("retrying release after the failure: %v", err)
	}
	if m.memory != nil {
		t.Error("the successful retry did not clear the mapping")
	}
}

// TestMemoryEnclave_FailedReleaseKeepsTheReservation pins that a refused release
// returns ErrLockedMemoryUnavailable without panicking, keeps the Allocator
// reservation while the kernel holds the pages, and that a retried Destroy
// refunds it exactly once.
func TestMemoryEnclave_FailedReleaseKeepsTheReservation(t *testing.T) {
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.NewSized(64)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}

	reserved := a.InUse()
	if reserved == 0 {
		t.Fatal("nothing was reserved; the test would be vacuous")
	}

	lift := denyProtectAndUnmap(t)

	var derr error
	if r := panicValue(func() { derr = e.Destroy() }); r != nil {
		t.Fatalf("Destroy panicked with %v; it never panics", r)
	}
	if !errors.Is(derr, ErrLockedMemoryUnavailable) {
		t.Errorf("Destroy = %v after failing to release the pages, want ErrLockedMemoryUnavailable", derr)
	}

	if got := a.InUse(); got != reserved {
		t.Errorf("InUse = %d after a FAILED release, want the unchanged %d: the budget "+
			"reported pages as available while the kernel still held them", got, reserved)
	}
	if e.m == nil {
		t.Fatal("the enclave discarded a mapping it never released")
	}
	// The mapping is retained but the enclave is not alive: the mapping was
	// writable, so the early wipe already destroyed the material. The retry
	// consults the mapping, not the wiped flag.
	if e.IsAlive() {
		t.Error("IsAlive = true although the early wipe already destroyed the " +
			"material; the caller would read zeroes and not be told")
	}

	lift()
	e.Destroy()

	if got := a.InUse(); got != 0 {
		t.Errorf("InUse = %d after the successful retry, want 0", got)
	}
	if e.IsAlive() {
		t.Error("IsAlive = true after a successful Destroy")
	}
}

// TestCoreDumpsDisabled pins that CoreDumpsDisabled is stable. Its value depends
// on the environment (a sandbox may deny setrlimit), so only the result is logged.
func TestCoreDumpsDisabled(t *testing.T) {
	first := CoreDumpsDisabled()
	if second := CoreDumpsDisabled(); !errors.Is(second, first) && second != first {
		t.Errorf("CoreDumpsDisabled is not stable: %v then %v", first, second)
	}
	if first == nil {
		t.Log("core dumps disabled process-wide")
	} else {
		t.Logf("core dumps NOT disabled: %v", first)
	}
}

// TestMapping_WipesMaterialBeforeAnySyscallThatCanFail pins that a writable
// mapping's material is zeroed before the first syscall that can be refused, so a
// denied mprotect leaves at worst an empty mapping.
func TestMapping_WipesMaterialBeforeAnySyscallThatCanFail(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	secret := bytes.Repeat([]byte{0xC3}, 64)
	copy(m.data, secret)
	if !bytes.Equal(m.data, secret) {
		t.Fatal("the material was not written; the test would be vacuous")
	}

	lift := denyProtect(t)

	err = m.wipeAndVerify()
	if err == nil {
		t.Fatal("wipeAndVerify reported success on a region it could not protect")
	}

	for i, c := range m.data {
		if c != 0 {
			t.Fatalf("data[%d] = %#x after a refused mprotect: the material survived on "+
				"locked pages the caller was told it could not have", i, c)
		}
	}

	lift()
	if err := m.release(); err != nil {
		t.Errorf("release after the refusal lifted: %v", err)
	}
}

// TestMapping_AbandonReleasesAPartialMapping pins the constructor's rollback: the
// pages go back, the error matches ErrLockedMemoryUnavailable and wraps the cause.
func TestMapping_AbandonReleasesAPartialMapping(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	cause := errors.New("induced construction failure")
	got := m.abandon(cause, true)

	if !errors.Is(got, ErrLockedMemoryUnavailable) {
		t.Errorf("abandon = %v, want it to match ErrLockedMemoryUnavailable", got)
	}
	if !errors.Is(got, cause) {
		t.Errorf("abandon = %v, want the original cause to remain reachable", got)
	}

	// A second release must fail rather than double-free.
	if second := m.abandon(cause, true); second == nil {
		t.Error("abandon reported success unmapping an already-released region")
	}
}

// TestMapping_CorruptionIsStickyAcrossAFailedRelease pins that a detected canary
// corruption is reported on every attempt, including the retry that finally
// releases, even though the first attempt wiped the canary. Held attempts must
// also classify as not released.
func TestMapping_CorruptionIsStickyAcrossAFailedRelease(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	if len(m.canary) == 0 {
		t.Fatal("a 32-byte mapping has no canary slack; the layout changed and this test is vacuous")
	}
	m.canary[len(m.canary)-1] ^= 0xFF

	denied := errors.New("munlock: cannot allocate memory")
	prev := unlockMemory
	t.Cleanup(func() {
		unlockMemory = prev
		if m.memory != nil {
			_ = m.release()
		}
	})
	unlockMemory = func([]byte) error { return denied }

	for attempt := 1; attempt <= 2; attempt++ {
		err = m.release()
		if !errors.Is(err, ErrEnclaveCorrupted) {
			t.Fatalf("held attempt %d = %v, want ErrEnclaveCorrupted: the detection must not be lost "+
				"because the release after it was refused", attempt, err)
		}
		if !errors.Is(err, denied) || !errors.Is(err, ErrLockedMemoryUnavailable) {
			t.Errorf("held attempt %d = %v, want the refused munlock reported alongside the corruption", attempt, err)
		}
		if releasedPages(err) {
			t.Fatalf("releasedPages(%v) = true on held attempt %d; the pages are still mapped", err, attempt)
		}
		if m.memory == nil {
			t.Fatalf("held attempt %d dropped the mapping; there is no handle left to retry through", attempt)
		}
	}

	unlockMemory = prev
	err = m.release()
	if !errors.Is(err, ErrEnclaveCorrupted) {
		t.Fatalf("the release that returned the pages = %v, want ErrEnclaveCorrupted: the retry "+
			"re-verified a canary its own first attempt had wiped", err)
	}
	if errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Errorf("the release that returned the pages = %v still reports a refusal", err)
	}
	if !releasedPages(err) {
		t.Errorf("releasedPages(%v) = false although the pages went back", err)
	}
	if m.memory != nil {
		t.Error("the mapping was not released by the successful retry")
	}
}

// TestMapping_RetryDoesNotReverify pins that a retry after a refused release does
// not re-verify the already-wiped canary. A re-verify of a clean mapping would
// pass silently, so the assertion counts the protection syscalls it needs.
func TestMapping_RetryDoesNotReverify(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	prevUnlock, prevProtect := unlockMemory, protectMemory
	t.Cleanup(func() {
		unlockMemory, protectMemory = prevUnlock, prevProtect
		if m.memory != nil {
			_ = m.release()
		}
	})
	unlockMemory = func([]byte) error { return errors.New("munlock refused") }

	if err := m.release(); err == nil || releasedPages(err) {
		t.Fatalf("release with a refused munlock = %v, want a held failure", err)
	}

	unlockMemory = prevUnlock
	protects := 0
	protectMemory = func(b []byte, p protection) error {
		protects++
		return prevProtect(b, p)
	}
	if err := m.release(); err != nil {
		t.Fatalf("retry = %v, want nil for a clean mapping", err)
	}
	if protects != 0 {
		t.Errorf("the retry re-opened the region %d times to verify a canary it had already wiped", protects)
	}
}

// TestMapping_AbandonReportsWhetherLockedPagesWereLeft pins the two predicates on
// abandon's error: pagesHeld (still mapped, mapping handed over for the orphan
// ledger) and lockedPagesHeld (still locked, so admission must not refund the
// charge). Mapped-but-unlocked pages are held but not locked.
func TestMapping_AbandonReportsWhetherLockedPagesWereLeft(t *testing.T) {
	cause := errors.New("the step that failed")
	refused := func([]byte) error { return errors.New("refused") }

	for _, tc := range []struct {
		name                 string
		unlock, unmap        bool // whether each step is refused
		wantHeld, wantLocked bool
	}{
		{"clean rollback", false, false, false, false},
		{"munlock refused, munmap took the lock with it", true, false, false, false},
		{"unlocked, but the munmap was refused", false, true, true, false},
		{"munlock and munmap refused", true, true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := newMapping(64)
			if err != nil {
				t.Fatalf("newMapping: %v", err)
			}
			memory := m.memory

			prevUnlock, prevUnmap := unlockMemory, unmapMemory
			restore := func() { unlockMemory, unmapMemory = prevUnlock, prevUnmap }
			t.Cleanup(restore)
			if tc.unlock {
				unlockMemory = refused
			}
			unmaps := 0
			unmapMemory = func(b []byte) error {
				unmaps++
				if tc.unmap {
					return errors.New("refused")
				}
				return prevUnmap(b)
			}

			err = m.abandon(cause, true)
			restore()

			if !errors.Is(err, cause) || !errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Errorf("abandon = %v, want the original cause as ErrLockedMemoryUnavailable", err)
			}
			if got := pagesHeld(err); got != tc.wantHeld {
				t.Errorf("pagesHeld(%v) = %v, want %v", err, got, tc.wantHeld)
			}
			if got := lockedPagesHeld(err); got != tc.wantLocked {
				t.Errorf("lockedPagesHeld(%v) = %v, want %v", err, got, tc.wantLocked)
			}
			var held *pagesHeldError
			if errors.As(err, &held) && held.orphan != m {
				t.Errorf("abandon left pages held without handing over the mapping that holds them")
			}
			// Exactly one unmap: a refused munlock must not skip it, and nothing
			// retries it behind the caller's back.
			if unmaps != 1 {
				t.Errorf("abandon unmapped %d times, want exactly 1", unmaps)
			}

			// Unmap what a refused row left behind so later tests start clean.
			if tc.unmap {
				if err := sysUnmap(memory); err != nil {
					t.Errorf("cleanup munmap: %v", err)
				}
			}
		})
	}
}

// TestMapping_ReleaseIsExactlyItsExplicitSteps records every seam call during
// release and pins the exact sequence (writable, wipe, munlock, munmap), with the
// mapping zero at the unlock and the unmap. The denied row is the one path that
// unmaps without the wipe, and it must skip the unlock.
func TestMapping_ReleaseIsExactlyItsExplicitSteps(t *testing.T) {
	for _, tc := range []struct {
		name      string
		freeze    bool
		deny      bool
		wantSteps []string
		wantErr   error
	}{
		{"writable", false, false, []string{"protect rw memory", "unlock inner", "unmap memory"}, nil},
		{"frozen", true, false, []string{"protect rw memory", "unlock inner", "unmap memory"}, nil},
		{"frozen, mprotect denied", true, true, []string{"protect rw memory", "unmap memory"}, ErrReleasedWithoutWipe},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, err := newMapping(64)
			if err != nil {
				t.Fatalf("newMapping: %v", err)
			}
			copy(m.data, bytes.Repeat([]byte{0xE7}, 64))
			if tc.freeze {
				if err := m.freeze(); err != nil {
					t.Fatalf("freeze: %v", err)
				}
			}
			memory, inner := m.memory, m.inner

			region := func(b []byte) string {
				switch {
				case &b[0] == &memory[0] && len(b) == len(memory):
					return "memory"
				case &b[0] == &inner[0] && len(b) == len(inner):
					return "inner"
				default:
					return "other"
				}
			}
			names := map[protection]string{protNoAccess: "none", protReadOnly: "ro", protReadWrite: "rw"}
			wipedAt := map[string]bool{}

			var steps []string
			prevProtect, prevUnlock, prevUnmap := protectMemory, unlockMemory, unmapMemory
			t.Cleanup(func() { protectMemory, unlockMemory, unmapMemory = prevProtect, prevUnlock, prevUnmap })
			protectMemory = func(b []byte, p protection) error {
				steps = append(steps, "protect "+names[p]+" "+region(b))
				if tc.deny {
					return errors.New("mprotect denied by policy")
				}
				return prevProtect(b, p)
			}
			unlockMemory = func(b []byte) error {
				steps = append(steps, "unlock "+region(b))
				wipedAt["unlock"] = bytes.Equal(memory, make([]byte, len(memory)))
				return prevUnlock(b)
			}
			unmapMemory = func(b []byte) error {
				steps = append(steps, "unmap "+region(b))
				// On the denied row the guards stay inaccessible, so the
				// whole-mapping read is skipped.
				if !tc.deny {
					wipedAt["unmap"] = bytes.Equal(memory, make([]byte, len(memory)))
				}
				return prevUnmap(b)
			}

			err = m.release()
			if tc.wantErr == nil && err != nil {
				t.Fatalf("release = %v, want nil", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("release = %v, want %v", err, tc.wantErr)
			}
			if !slices.Equal(steps, tc.wantSteps) {
				t.Errorf("release made %q, want exactly %q", steps, tc.wantSteps)
			}
			for step, wiped := range wipedAt {
				if !wiped {
					t.Errorf("the mapping still held non-zero bytes at the %s: the wipe did not precede it", step)
				}
			}
			if m.memory != nil {
				t.Error("the mapping kept its handle after the pages went back")
			}
		})
	}
}

// errNotLocked is installStrictUnlock's refusal of a repeated unlock, mirroring
// Windows' ERROR_NOT_LOCKED (Linux's munlock tolerates the repeat).
var errNotLocked = errors.New("VirtualUnlock: ERROR_NOT_LOCKED")

// installStrictUnlock gives unlockMemory VirtualUnlock's semantics: a second
// unlock of the same region fails with errNotLocked. It restores the seam via
// t.Cleanup, so register cleanups that need the real unlock before calling it.
func installStrictUnlock(t *testing.T) {
	t.Helper()
	prev := unlockMemory
	t.Cleanup(func() { unlockMemory = prev })

	var mu sync.Mutex
	unlocked := make(map[*byte]struct{})
	unlockMemory = func(b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		if _, done := unlocked[&b[0]]; done {
			return errNotLocked
		}
		if err := prev(b); err != nil {
			return err
		}
		unlocked[&b[0]] = struct{}{}
		return nil
	}
}

// TestMapping_RetryAfterARefusedUnmapDoesNotUnlockAgain pins that after a
// successful munlock and a refused munmap, the retry does not unlock again (which
// Windows refuses, stranding the mapping) and that the held attempt reports the
// pages as not locked.
func TestMapping_RetryAfterARefusedUnmapDoesNotUnlockAgain(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	prevUnmap := unmapMemory
	t.Cleanup(func() {
		unmapMemory = prevUnmap
		if m.memory != nil {
			_ = m.release()
		}
	})
	installStrictUnlock(t)

	unmaps := 0
	unmapMemory = func(b []byte) error {
		unmaps++
		if unmaps == 1 {
			return errors.New("munmap: cannot allocate memory")
		}
		return prevUnmap(b)
	}

	err = m.release()
	if !pagesHeld(err) {
		t.Fatalf("release with a refused munmap = %v, want a held failure", err)
	}
	if lockedPagesHeld(err) {
		t.Errorf("lockedPagesHeld(%v) = true, want false: the munlock succeeded", err)
	}

	err = m.release()
	if errors.Is(err, errNotLocked) {
		t.Fatalf("the retry unlocked the region a second time and was refused (%v); on Windows the "+
			"mapping can then never be released", err)
	}
	if err != nil {
		t.Fatalf("retry = %v, want nil once the munmap is allowed", err)
	}
	if unmaps != 2 {
		t.Errorf("munmap attempted %d times, want 2: the retry never reached it", unmaps)
	}
	if m.memory != nil {
		t.Error("the mapping is still held after the retry released the pages")
	}
}

// TestNewMapping_EveryConstructionStepRollsBack fails each step of newMapping
// in turn, through the public constructor, and asserts the rollback: the
// region is unlocked if it had been locked, unmapped once, reported as held
// only when the unmap was refused, and a held region is adopted as an orphan
// that a later WipeAll reclaims.
func TestNewMapping_EveryConstructionStepRollsBack(t *testing.T) {
	type seams struct {
		lock, unlock, unmap func([]byte) error
		protect             func([]byte, protection) error
		core, fork, canary  func([]byte) error
	}
	saved := seams{lockMemory, unlockMemory, unmapMemory, protectMemory, excludeCoreDump, excludeFork, fillCanary}
	restore := func() {
		lockMemory, unlockMemory, unmapMemory, protectMemory = saved.lock, saved.unlock, saved.unmap, saved.protect
		excludeCoreDump, excludeFork, fillCanary = saved.core, saved.fork, saved.canary
	}
	t.Cleanup(restore)

	cause := errors.New("the step that failed")
	fail := func([]byte) error { return cause }
	// guardFailure fails the nth guard-page mprotect (1 = preguard).
	guardFailure := func(nth int) func() {
		return func() {
			calls := 0
			protectMemory = func(b []byte, p protection) error {
				if p == protNoAccess {
					calls++
					if calls == nth {
						return cause
					}
				}
				return saved.protect(b, p)
			}
		}
	}

	steps := []struct {
		name   string
		inject func()
		locked bool
	}{
		{"mlock", func() { lockMemory = fail }, false},
		{"core-dump exclusion", func() { excludeCoreDump = fail }, true},
		{"fork exclusion", func() { excludeFork = fail }, true},
		{"canary fill", func() { fillCanary = fail }, true},
		{"preguard mprotect", guardFailure(1), true},
		{"postguard mprotect", guardFailure(2), true},
	}
	cleanups := []struct {
		name                        string
		unlockRefused, unmapRefused bool
	}{
		{"clean rollback", false, false},
		{"munmap refused", false, true},
		{"munlock and munmap refused", true, true},
	}

	for _, step := range steps {
		for _, cl := range cleanups {
			t.Run(step.name+"/"+cl.name, func(t *testing.T) {
				requireCleanLedger(t)
				t.Cleanup(restore)
				step.inject()

				unlocks, unmaps := 0, 0
				unlockMemory = func(b []byte) error {
					unlocks++
					if cl.unlockRefused {
						return errors.New("munlock refused")
					}
					return saved.unlock(b)
				}
				unmapMemory = func(b []byte) error {
					unmaps++
					if cl.unmapRefused {
						return errors.New("munmap refused")
					}
					return saved.unmap(b)
				}

				e, err := NewMemoryEnclaveSized(64)
				restore()

				if e != nil {
					t.Fatalf("NewMemoryEnclaveSized returned an enclave although %s failed", step.name)
				}
				if !errors.Is(err, cause) || !errors.Is(err, ErrLockedMemoryUnavailable) {
					t.Errorf("err = %v, want the failed step as ErrLockedMemoryUnavailable", err)
				}
				wantUnlocks := 0
				if step.locked {
					wantUnlocks = 1
				}
				if unlocks != wantUnlocks {
					t.Errorf("munlock called %d times, want %d", unlocks, wantUnlocks)
				}
				if unmaps != 1 {
					t.Errorf("munmap called %d times, want 1", unmaps)
				}
				if got := pagesHeld(err); got != cl.unmapRefused {
					t.Errorf("pagesHeld(%v) = %v, want %v", err, got, cl.unmapRefused)
				}
				wantLocked := step.locked && cl.unlockRefused && cl.unmapRefused
				if got := lockedPagesHeld(err); got != wantLocked {
					t.Errorf("lockedPagesHeld(%v) = %v, want %v", err, got, wantLocked)
				}

				wantOrphans := 0
				if cl.unmapRefused {
					wantOrphans = 1
				}
				if got := orphanCount(); got != wantOrphans {
					t.Errorf("orphan ledger holds %d, want %d", got, wantOrphans)
				}
				if remaining := sweep(t); remaining != 0 {
					t.Errorf("WipeAll left %d entries once the refusals lifted, want 0", remaining)
				}
			})
		}
	}
}

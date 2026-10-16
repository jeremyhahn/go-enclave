// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// guardMarker selects the guard-page test's child and names the guard.
	guardMarker = "GO_ENCLAVE_GUARD_WRITE"

	// guardArmed is printed just before the store into the guard, so a child that
	// died earlier (a refused mapping, say) is not mistaken for the fault.
	guardArmed = "mapped; writing to the guard page now"

	// guardSurvived is printed only if the store into the guard returned.
	guardSurvived = "wrote to a guard page and lived"
)

// TestMapping_GuardPagesFault pins that a write to either guard page faults. A
// fault on a PROT_NONE page outside the Go heap is unrecoverable, so the write
// runs in a subprocess that must die without printing guardSurvived.
func TestMapping_GuardPagesFault(t *testing.T) {
	if guard := os.Getenv(guardMarker); guard != "" {
		guardWriteChild(t, guard)
		return
	}

	for _, guard := range []string{"pre", "post"} {
		t.Run(guard, func(t *testing.T) {
			out, err := runTestChild(t, "TestMapping_GuardPagesFault", guardMarker, guard)
			requireChildFaulted(t, out, err, guardArmed, guardSurvived, "writing to the "+guard+"guard")
		})
	}
}

func guardWriteChild(t *testing.T, guard string) {
	t.Helper()

	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	target := m.preguard
	if guard == "post" {
		target = m.postguard
	}
	fmt.Println(guardArmed)

	// Never returns if the page is PROT_NONE.
	target[0] = 0xFF

	fmt.Println(guardSurvived)
	_ = m.release()
}

const (
	// leakMarker selects the child half of the failed-mapping leak test.
	leakMarker = "GO_ENCLAVE_ALLOC_LEAK"

	leakFaultArmed = "mappings failed under the injected ceiling"

	leakNone = "failed mappings released everything they took"
)

// TestMapping_FailedAllocationLeaksNothing pins that a constructor whose mlock
// fails (RLIMIT_MEMLOCK forced to zero) gives back everything it mapped, measured
// by the kernel's VmLck and the /proc/self/maps line count. It runs in a
// subprocess because it lowers the process's memlock ceiling.
func TestMapping_FailedAllocationLeaksNothing(t *testing.T) {
	if os.Getenv(leakMarker) == "1" {
		allocLeakChild(t)
		return
	}

	out, err := runTestChild(t, "TestMapping_FailedAllocationLeaksNothing", leakMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	for _, want := range []string{leakFaultArmed, leakNone} {
		if !strings.Contains(out, want) {
			t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
		}
	}
}

func allocLeakChild(t *testing.T) {
	t.Helper()

	// Every mapping below gets as far as mmap and then fails at mlock.
	setCeiling, _ := injectMemlockCeiling(t)
	setCeiling(0)

	lockedBefore, err := vmLckBytes()
	if err != nil {
		t.Fatalf("cannot read VmLck: %v", err)
	}
	vmasBefore, err := vmaCount()
	if err != nil {
		t.Fatalf("cannot read /proc/self/maps: %v", err)
	}

	const attempts = 256
	failures := 0
	for i := 0; i < attempts; i++ {
		e, err := newMemorySized(64)
		if err == nil {
			e.Destroy()
			continue
		}
		if !errors.Is(err, ErrLockedMemoryUnavailable) {
			t.Fatalf("err = %v, want ErrLockedMemoryUnavailable", err)
		}
		failures++
	}

	if failures == 0 {
		t.Fatalf("all %d mappings succeeded under a zero RLIMIT_MEMLOCK: the ceiling did not bind, the "+
			"fault was not armed, and the leak assertions below would be vacuous", attempts)
	}
	t.Logf("%s (%d/%d)", leakFaultArmed, failures, attempts)

	lockedAfter, err := vmLckBytes()
	if err != nil {
		t.Fatalf("cannot read VmLck: %v", err)
	}
	vmasAfter, err := vmaCount()
	if err != nil {
		t.Fatalf("cannot read /proc/self/maps: %v", err)
	}

	if lockedAfter != lockedBefore {
		t.Fatalf("VmLck = %d after %d failed mappings, want the starting %d (locked pages leaked)",
			lockedAfter, failures, lockedBefore)
	}
	// The runtime maps on its own account, so allow drift that does not scale
	// with the failures; a per-failure leak of three VMAs would be ~768.
	if drift := vmasAfter - vmasBefore; drift > 16 {
		t.Fatalf("VMA count drifted by %d over %d failed mappings, want no growth that scales with them "+
			"(%d before, %d after)", drift, failures, vmasBefore, vmasAfter)
	}
	t.Log(leakNone)
}

const (
	// rollbackMarker selects the child half of the copy-constructor rollback test.
	rollbackMarker = "GO_ENCLAVE_COPY_ROLLBACK"

	rollbackNone = "failed copy constructors returned locked memory to its baseline"
)

// TestNewFrozenCopy_FailedConstructionReturnsToBaseline pins the rollback of
// every copying constructor (NewMemory, NewMemoryCopy, Allocator.New) on both
// of its failure paths: a refused mlock, from a real RLIMIT_MEMLOCK ceiling,
// and a refused freeze of pages already mapped and locked. Afterwards VmLck,
// the allocator's InUse and the shutdown ledger are back where they started.
// It runs in a subprocess because it lowers the process's memlock ceiling.
func TestNewFrozenCopy_FailedConstructionReturnsToBaseline(t *testing.T) {
	if os.Getenv(rollbackMarker) == "1" {
		copyRollbackChild(t)
		return
	}

	out, err := runTestChild(t, "TestNewFrozenCopy_FailedConstructionReturnsToBaseline", rollbackMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, rollbackNone) {
		t.Fatalf("subprocess did not confirm %q:\n%s", rollbackNone, out)
	}
}

func copyRollbackChild(t *testing.T) {
	t.Helper()
	requireCleanLedger(t)

	// A budget large enough that only the OS can refuse.
	a, err := newBudgetAllocator(1 << 20)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	constructors := []struct {
		name  string
		build func([]byte) (*lockedRegion, error)
	}{
		{"NewMemory", newMemory},
		{"NewMemoryCopy", newMemoryCopy},
		{"Allocator.New", a.admitData},
	}

	setCeiling, original := injectMemlockCeiling(t)
	failures := []struct {
		name string
		arm  func() (lift func())
	}{
		// mmap succeeds and mlock is refused, so the pages are unmapped unlocked.
		{"mlock refused", func() func() {
			setCeiling(0)
			return func() { setCeiling(original.Cur) }
		}},
		// The pages are mapped and locked; only the freeze is refused.
		{"freeze refused", func() func() { return denyProtect(t) }},
	}

	lockedBefore, err := vmLckBytes()
	if err != nil {
		t.Fatalf("cannot read VmLck: %v", err)
	}

	const attempts = 64
	for _, f := range failures {
		for _, c := range constructors {
			lift := f.arm()
			for i := 0; i < attempts; i++ {
				e, err := c.build([]byte(fmt.Sprintf("rollback-material-%d", i)))
				if e != nil {
					t.Fatalf("%s/%s: returned an enclave although construction failed", f.name, c.name)
				}
				if !errors.Is(err, ErrLockedMemoryUnavailable) {
					t.Fatalf("%s/%s: err = %v, want ErrLockedMemoryUnavailable", f.name, c.name, err)
				}
				if errors.Is(err, ErrReleasedWithoutWipe) {
					t.Fatalf("%s/%s: err = %v; the rollback could not wipe and release", f.name, c.name, err)
				}
			}
			lift()

			lockedAfter, err := vmLckBytes()
			if err != nil {
				t.Fatalf("cannot read VmLck: %v", err)
			}
			if lockedAfter != lockedBefore {
				t.Fatalf("%s/%s: VmLck = %d after %d failures, want the starting %d (locked pages leaked)",
					f.name, c.name, lockedAfter, attempts, lockedBefore)
			}
			if a.InUse() != 0 {
				t.Fatalf("%s/%s: InUse = %d after the failures, want 0 (a reservation leaked)",
					f.name, c.name, a.InUse())
			}
			if remaining := sweep(t); remaining != 0 {
				t.Fatalf("%s/%s: WipeAll found %d held entries, want 0 (the ledger leaked)",
					f.name, c.name, remaining)
			}
		}
	}
	t.Log(rollbackNone)
}

// vmaCount reports how many mappings the process currently holds.
func vmaCount() (int, error) {
	b, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return 0, err
	}
	return len(strings.Split(strings.TrimSpace(string(b)), "\n")), nil
}

const (
	// frozenMarker selects the child half of the frozen-pages test.
	frozenMarker = "GO_ENCLAVE_FROZEN_WRITE"

	// frozenArmed is printed just before the store, for the reason on guardArmed.
	frozenArmed = "move-constructed and opened; writing through the view now"

	// frozenSurvived is printed only if a write through a move-constructed enclave's
	// view returned.
	frozenSurvived = "wrote through a move-constructed enclave and lived"
)

// TestMemory_MoveConstructedPagesAreReadOnly pins both halves of the
// constructor difference: a sized enclave is writable in-process, and a write
// through a move-constructed enclave's view faults (in a subprocess). Either half
// alone would pass against a build that froze everything or nothing.
func TestMemory_MoveConstructedPagesAreReadOnly(t *testing.T) {
	if os.Getenv(frozenMarker) == "1" {
		frozenWriteChild(t)
		return
	}

	sized, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	if err := sized.WithBytes(func(b []byte) error {
		b[0] = 0xFF // must not fault: this is the fill path
		return nil
	}); err != nil {
		t.Fatalf("filling a sized enclave: %v", err)
	}
	if !holds(sized, append([]byte{0xFF}, make([]byte, 31)...)) {
		t.Error("the write into a sized enclave did not take")
	}
	sized.Destroy()

	out, cerr := runTestChild(t, "TestMemory_MoveConstructedPagesAreReadOnly", frozenMarker, "1")
	requireChildFaulted(t, out, cerr, frozenArmed, frozenSurvived,
		"a write through a move-constructed enclave (its pages are not frozen)")
}

func frozenWriteChild(t *testing.T) {
	t.Helper()

	e, err := newMemory([]byte("private-key-material"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}

	view := e.m.data // a slice no lock covers, as a careless caller would keep
	fmt.Println(frozenArmed)

	view[0] = 0xFF

	fmt.Println(frozenSurvived)
	e.Destroy()
}

const (
	// copyFrozenMarker selects the child half of the copy-constructor frozen test.
	// It needs its own child because the write under test kills the process.
	copyFrozenMarker = "GO_ENCLAVE_COPY_FROZEN_WRITE"

	// copyFrozenArmed is printed just before the store, for the reason on guardArmed.
	copyFrozenArmed = "copy-constructed and opened; writing through the view now"

	// copyFrozenSurvived is printed only if a write through a copy-constructed
	// enclave's view returned.
	copyFrozenSurvived = "wrote through a copy-constructed enclave and lived"
)

// TestMemory_CopyConstructedPagesAreReadOnly pins that the copy
// constructor's pages are read-only as enforced by the MMU, not only as recorded
// by the mapping's flag (TestNewMemoryCopy_PagesAreFrozen). The write runs
// in a subprocess because succeeding at it kills the process.
func TestMemory_CopyConstructedPagesAreReadOnly(t *testing.T) {
	if os.Getenv(copyFrozenMarker) == "1" {
		copyFrozenWriteChild(t)
		return
	}

	out, cerr := runTestChild(t, "TestMemory_CopyConstructedPagesAreReadOnly", copyFrozenMarker, "1")
	requireChildFaulted(t, out, cerr, copyFrozenArmed, copyFrozenSurvived,
		"a write through a copy-constructed enclave (its pages are not frozen)")
}

func copyFrozenWriteChild(t *testing.T) {
	t.Helper()

	src := []byte("private-key-material")
	e, err := newMemoryCopy(src)
	if err != nil {
		t.Fatalf("NewMemoryCopy: %v", err)
	}

	// The caller's source stays writable; only the enclave's view may fault.
	src[0] = 0xFE

	view := e.m.data // a slice no lock covers, as a careless caller would keep
	fmt.Println(copyFrozenArmed)

	view[0] = 0xFF

	fmt.Println(copyFrozenSurvived)
	e.Destroy()
}

// TestExcludeFromCoreDump_ReportsRefusal pins that excludeFromCoreDump returns
// the kernel's refusal. madvise rejects an unaligned address with EINVAL, so the
// failure needs no seam. The call site in newMapping is covered by
// TestNewMapping_EveryConstructionStepRollsBack.
func TestExcludeFromCoreDump_ReportsRefusal(t *testing.T) {
	region, err := sysMap(2 * int(pageSize))
	if err != nil {
		t.Fatalf("could not allocate the probe region: %v", err)
	}
	defer func() {
		if err := sysUnmap(region); err != nil {
			t.Errorf("freeing the probe region: %v", err)
		}
	}()

	// Control: an aligned region must succeed, or the check below is vacuous.
	if err := excludeFromCoreDump(region); err != nil {
		t.Fatalf("excludeFromCoreDump on an aligned region: %v", err)
	}

	// mmap returns a page-aligned base, so base+1 is unaligned: EINVAL.
	err = excludeFromCoreDump(region[1:])
	if err == nil {
		t.Fatal("excludeFromCoreDump reported success on an unaligned region: " +
			"the kernel's refusal is being swallowed, and enclave pages could reach a core file")
	}
	requireMadviseError(t, err)
}

// requireMadviseError asserts err is the madvise EINVAL as an *os.SyscallError,
// the form every other system call in this package reports.
func requireMadviseError(t *testing.T, err error) {
	t.Helper()
	var se *os.SyscallError
	if !errors.As(err, &se) || se.Syscall != "madvise" {
		t.Errorf("err = %#v, want an *os.SyscallError for madvise", err)
	}
	if !errors.Is(err, unix.EINVAL) {
		t.Errorf("err = %v, want EINVAL reachable", err)
	}
}

// TestExcludeFromFork_ReportsRefusal is the fork-exclusion twin of
// TestExcludeFromCoreDump_ReportsRefusal: an unaligned region is EINVAL.
func TestExcludeFromFork_ReportsRefusal(t *testing.T) {
	region, err := sysMap(2 * int(pageSize))
	if err != nil {
		t.Fatalf("could not allocate the probe region: %v", err)
	}
	defer func() {
		if err := sysUnmap(region); err != nil {
			t.Errorf("freeing the probe region: %v", err)
		}
	}()

	if err := excludeFromFork(region); err != nil {
		t.Fatalf("excludeFromFork on an aligned region: %v", err)
	}
	err = excludeFromFork(region[1:])
	if err == nil {
		t.Fatal("excludeFromFork reported success on an unaligned region")
	}
	requireMadviseError(t, err)
}

// TestNewMapping_KernelRecordsTheExclusions reads the kernel's own VMA flags
// for a fresh mapping: every page, guards included, is "dc" (MADV_DONTFORK),
// and the data region is "dd" (MADV_DONTDUMP).
func TestNewMapping_KernelRecordsTheExclusions(t *testing.T) {
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	defer func() {
		if err := m.release(); err != nil {
			t.Errorf("release: %v", err)
		}
	}()

	for _, region := range []struct {
		name string
		b    []byte
		want []string
	}{
		{"preguard", m.preguard, []string{"dc"}},
		{"inner", m.inner, []string{"dc", "dd"}},
		{"postguard", m.postguard, []string{"dc"}},
	} {
		flags := vmFlagsAt(t, uintptr(unsafe.Pointer(&region.b[0])))
		for _, f := range region.want {
			if !slices.Contains(flags, f) {
				t.Errorf("%s VmFlags = %v, want %q", region.name, flags, f)
			}
		}
	}
}

// vmFlagsAt returns the VmFlags /proc/self/smaps reports for the mapping
// containing addr.
func vmFlagsAt(t *testing.T, addr uintptr) []string {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/smaps")
	if err != nil {
		t.Fatalf("read /proc/self/smaps: %v", err)
	}
	in := false
	for _, line := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(line); len(f) > 0 && strings.Contains(f[0], "-") && !strings.HasSuffix(f[0], ":") {
			lo, hi, ok := strings.Cut(f[0], "-")
			l, err1 := strconv.ParseUint(lo, 16, 64)
			h, err2 := strconv.ParseUint(hi, 16, 64)
			in = ok && err1 == nil && err2 == nil && uint64(addr) >= l && uint64(addr) < h
			continue
		}
		if in && strings.HasPrefix(line, "VmFlags:") {
			return strings.Fields(strings.TrimPrefix(line, "VmFlags:"))
		}
	}
	t.Fatalf("no VmFlags found for %#x in /proc/self/smaps", addr)
	return nil
}

// mappedAt reports whether addr still falls inside any mapping of this process.
// It reads /proc/self/maps rather than touching addr, which would either succeed
// silently or kill the process.
func mappedAt(t *testing.T, addr uintptr) bool {
	t.Helper()

	f, err := os.Open("/proc/self/maps")
	if err != nil {
		t.Fatalf("open /proc/self/maps: %v", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		dash := strings.IndexByte(line, '-')
		sp := strings.IndexByte(line, ' ')
		if dash < 0 || sp < 0 || sp < dash {
			continue
		}
		lo, err1 := strconv.ParseUint(line[:dash], 16, 64)
		hi, err2 := strconv.ParseUint(line[dash+1:sp], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if uint64(addr) >= lo && uint64(addr) < hi {
			return true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan /proc/self/maps: %v", err)
	}
	return false
}

// TestFrozenReleaseUnmapsWhenMprotectIsDenied pins that a frozen enclave whose
// release mprotect is permanently denied is unmapped anyway, so the material does
// not stay resident, and that release reports ErrReleasedWithoutWipe wrapping the
// denial.
func TestFrozenReleaseUnmapsWhenMprotectIsDenied(t *testing.T) {
	secret := []byte("material that must not stay resident")

	// Unexported constructor: this test calls m.release() rather than
	// Destroy, so a ledger-registered enclave would stay registered and skew
	// every WipeAll test.
	e, err := unpublishedCopy(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}

	if e.m.mutable {
		t.Fatal("enclave is not frozen, so this test would pass without " +
			"covering the frozen path")
	}

	addr := uintptr(unsafe.Pointer(&e.m.memory[0]))
	if !mappedAt(t, addr) {
		t.Fatal("the region is not mapped before release, so the assertion " +
			"after it would be vacuous")
	}

	denied := errors.New("mprotect denied by policy")
	swapSeam(t, &protectMemory, func([]byte, protection) error { return denied })

	rerr := e.m.release()

	if !errors.Is(rerr, ErrReleasedWithoutWipe) {
		t.Fatalf("release = %v, want ErrReleasedWithoutWipe: a denied mprotect "+
			"on a frozen enclave must fall back to unmapping, and must say so", rerr)
	}
	if !errors.Is(rerr, denied) {
		t.Errorf("release = %v, want the underlying mprotect refusal reachable "+
			"through errors.Is; an operator needs to know what denied it", rerr)
	}

	if mappedAt(t, addr) {
		t.Fatal("the region is STILL MAPPED after release: the material is " +
			"resident in locked memory for the process lifetime, which is " +
			"exactly the frozen-path defect")
	}

	if e.m.memory != nil || e.m.data != nil || e.m.inner != nil {
		t.Error("the mapping kept its slices after the pages were unmapped; a " +
			"reader would be looking at memory the kernel has taken back")
	}
}

// TestFrozenReleaseKeepsTheMappingWhenTheBypassAlsoFails pins that when the
// fallback munmap is refused too, release reports a failure and keeps the mapping
// for a retry.
func TestFrozenReleaseKeepsTheMappingWhenTheBypassAlsoFails(t *testing.T) {
	e, err := unpublishedCopy([]byte("material"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	denied := errors.New("mprotect denied by policy")
	swapSeam(t, &protectMemory, func([]byte, protection) error { return denied })
	swapSeam(t, &unmapMemory, func([]byte) error { return errors.New("munmap denied too") })

	rerr := e.m.release()

	if errors.Is(rerr, ErrReleasedWithoutWipe) {
		t.Fatalf("release = %v, want a failure: the bypass did not run, so "+
			"claiming an unwiped RELEASE would report pages returned that were not", rerr)
	}
	if e.m.memory == nil {
		t.Fatal("the mapping was dropped although the pages are still mapped; " +
			"there is now no handle to retry the release through")
	}
}

// TestKeptMappingReadsAsDestroyedOnceWiped pins that a mapping kept after a
// successful wipe (its munlock or munmap refused) reads as destroyed: IsAlive is
// false, Size is 0, and Open, WithBytes and EqualTo return ErrEnclaveDestroyed
// rather than exposing zeroes.
func TestKeptMappingReadsAsDestroyedOnceWiped(t *testing.T) {
	e, err := unpublishedCopy([]byte("material that is about to be wiped"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	// wipeAndVerify alone produces the state a release leaves when the
	// munlock or munmap after the wipe is refused, with no syscall stub.
	if err := e.m.wipeAndVerify(); err != nil {
		t.Fatalf("wipeAndVerify: %v", err)
	}
	if !e.m.wiped {
		t.Fatal("wipeAndVerify did not record that the material is gone, so " +
			"this test cannot be asserting what it claims")
	}
	if e.m.memory == nil {
		t.Fatal("the mapping was released; this test needs the KEPT-mapping case")
	}

	if e.IsAlive() {
		t.Error("IsAlive reports true for an enclave whose material is gone")
	}
	if n := e.Size(); n != 0 {
		t.Errorf("Size = %d, want 0: there is no material left to have a size", n)
	}
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("WithBytes = %v, want ErrEnclaveDestroyed: it would otherwise lend "+
			"zeroes from a region whose guards are already read-write", err)
	}
	// The error, not the bool, shows the comparison did not run.
	if _, err := e.EqualTo([]byte("anything")); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("EqualTo = %v, want ErrEnclaveDestroyed: there is no "+
			"material left, so the comparison could not have run", err)
	}
}

// TestReleaseNeverUnmapsMaterialItCouldNotWipe pins that a refused wipe diverts
// release to the fallback rather than the ordinary teardown: no munlock, one
// munmap, the mprotect denial in the error, and the mapping not marked wiped.
func TestReleaseNeverUnmapsMaterialItCouldNotWipe(t *testing.T) {
	e, err := unpublishedCopy([]byte("material that must not be handed back unwiped"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	denied := errors.New("mprotect denied by policy")
	prevUnlock := unlockMemory
	unmaps, unlocks := 0, 0
	swapSeam(t, &protectMemory, func([]byte, protection) error { return denied })
	swapSeam(t, &unlockMemory, func(b []byte) error {
		unlocks++
		return prevUnlock(b)
	})
	swapSeam(t, &unmapMemory, func([]byte) error {
		unmaps++
		// Refused, so the mapping is kept for inspection.
		return errors.New("munmap denied too")
	})

	rerr := e.m.release()

	if !errors.Is(rerr, denied) {
		t.Errorf("release = %v, want the mprotect denial that diverted it to the fallback", rerr)
	}
	if !pagesHeld(rerr) {
		t.Errorf("pagesHeld(%v) = false, want true: the fallback unmap was refused", rerr)
	}
	if unlocks != 0 {
		t.Errorf("release unlocked %d times on a region it could not wipe: it carried on to the "+
			"ordinary teardown as though the wipe had happened", unlocks)
	}

	if e.m.wiped {
		t.Fatal("the mapping reports itself wiped although the wipe was refused")
	}
	if e.m.memory == nil {
		t.Fatal("release dropped a mapping it could not wipe: the pages may " +
			"still hold material and there is no handle left to retry through")
	}
	if unmaps != 1 {
		t.Errorf("the fallback unmap ran %d times for one release, want 1", unmaps)
	}
}

// TestKeptMutableMappingReadsAsDestroyedOnceWiped is the mutable-mapping branch of
// TestKeptMappingReadsAsDestroyedOnceWiped: the early wipe ran, then the mprotect
// and the fallback munmap were both refused, and the kept mapping must still read
// as destroyed.
func TestKeptMutableMappingReadsAsDestroyedOnceWiped(t *testing.T) {
	e, err := unpublishedSized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	if !e.m.mutable {
		t.Fatal("the mapping is not mutable, so wipeAndVerify's early wipe " +
			"would not run and this test would cover nothing")
	}
	if err := e.WithBytes(func(b []byte) error { copy(b, "material in a fillable enclave"); return nil }); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}

	denied := errors.New("mprotect denied by policy")
	swapSeam(t, &protectMemory, func([]byte, protection) error { return denied })
	swapSeam(t, &unmapMemory, func([]byte) error { return errors.New("munmap denied too") })

	_ = e.m.release()

	if e.m == nil || e.m.memory == nil {
		t.Fatal("the mapping was released; this test needs the KEPT-mapping case")
	}

	if e.IsAlive() {
		t.Error("IsAlive reports true for a mutable enclave whose material the " +
			"early wipe already destroyed")
	}
	if n := e.Size(); n != 0 {
		t.Errorf("Size = %d, want 0: there is no material left to have a size", n)
	}
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("WithBytes = %v, want ErrEnclaveDestroyed: it would otherwise lend "+
			"zeroes from a region whose guards are already read-write", err)
	}
	if _, err := e.EqualTo([]byte("anything")); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("EqualTo = %v, want ErrEnclaveDestroyed", err)
	}
}

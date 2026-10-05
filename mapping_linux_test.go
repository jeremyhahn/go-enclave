// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

package enclave

import (
	"bufio"
	"bytes"
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
	// guardMarker selects the child half of the guard-page test, and names which
	// guard it should write to.
	guardMarker = "GO_ENCLAVE_GUARD_WRITE"

	// guardArmed is printed by the child immediately before the store into the
	// guard. The parent requires it: a child that died before getting there —
	// a refused mapping, say — exits non-zero too, and would otherwise read as
	// the fault this test is looking for.
	guardArmed = "mapped; writing to the guard page now"

	// guardSurvived is printed by the child if a write to an inaccessible guard
	// page RETURNED. The parent treats seeing it as the failure: the guard is
	// not guarding.
	guardSurvived = "wrote to a guard page and lived"
)

// TestMapping_GuardPagesFault asserts the fence around every enclave is real.
//
// The data region sits flush against the postguard, so the first byte past the
// material is an inaccessible page: an overflow faults immediately instead of
// running on into whatever the allocator put next. The preguard closes the same
// door on the other side, past the canary.
//
// This has to run in a subprocess because a successful assertion KILLS the
// process — the fault is at a mapped-but-PROT_NONE address outside the Go heap,
// which the runtime reports as an unrecoverable fault rather than a catchable
// panic. So the evidence is inverted: the child must die, and must not have
// printed the survival marker first.
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

	// The write the guard exists to stop. If the page really is PROT_NONE this
	// never returns.
	target[0] = 0xFF

	// Only reachable if the guard is not guarding. Printed, then the mapping is
	// released so the parent's diagnosis is about the guard and not about a
	// leak.
	fmt.Println(guardSurvived)
	_ = m.release()
}

const (
	// leakMarker selects the child half of the failed-mapping leak test.
	leakMarker = "GO_ENCLAVE_ALLOC_LEAK"

	// leakFaultArmed is logged once the child has seen mappings actually fail.
	leakFaultArmed = "mappings failed under the injected ceiling"

	// leakNone is logged once the child has confirmed the failures left neither
	// locked pages nor address space behind.
	leakNone = "failed mappings released everything they took"
)

// TestMapping_FailedAllocationLeaksNothing covers the path memguard could not
// take: when locking fails, go-enclave has already mmap'd the region, and it has
// to give that back before returning the error.
//
// memguard's answer to the same situation is core.Panic — it never unwinds, so
// the question never arises for it. Ours returns an error, which means the
// cleanup is real code on a path that only runs under resource exhaustion, i.e.
// exactly the code most likely to be wrong and least likely to be exercised.
//
// The yardsticks come from the kernel and are independent of the package: VmLck
// for locked pages and the /proc/self/maps line count for address space. Both
// must return to where they started after a run of failures. A leak of either
// one is unbounded — the caller sees a typed error and retries.
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

	// Zero locked memory allowed, so every mapping below gets as far as mmap
	// and then fails at mlock — which is the path under test.
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
		e, err := NewMemoryEnclaveSized(64)
		if err == nil {
			// The ceiling did not bite; nothing to assert about cleanup.
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
	// Address space is noisier than VmLck — the Go runtime maps and unmaps on
	// its own account — so this allows drift that does not scale with the
	// failure count. A per-failure leak of three VMAs would be ~768 here.
	if drift := vmasAfter - vmasBefore; drift > 16 {
		t.Fatalf("VMA count drifted by %d over %d failed mappings, want no growth that scales with them "+
			"(%d before, %d after)", drift, failures, vmasBefore, vmasAfter)
	}
	t.Log(leakNone)
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

	// frozenArmed is printed by the child immediately before the store, for
	// the reason given on guardArmed.
	frozenArmed = "move-constructed and opened; writing through the view now"

	// frozenSurvived is printed by the child if a write through a
	// move-constructed enclave's borrow RETURNED. Seeing it is the failure: the
	// pages were never frozen and a stray write corrupts key material silently.
	frozenSurvived = "wrote through a move-constructed enclave and lived"
)

// TestMemoryEnclave_MoveConstructedPagesAreReadOnly pins the one behavioral
// difference between the two constructors, which the documentation on Open and
// NewMemoryEnclaveSized both promise.
//
// An enclave built from existing material has its pages frozen read-only once
// the material is in, so a write through a retained slice FAULTS. A sized
// enclave's pages must arrive writable — that is what makes generate-in-place
// possible — so the same write succeeds there until the caller freezes them
// itself, which is what [MemoryEnclave.Freeze] and
// TestMemoryEnclave_FrozenSizedPagesFault cover.
//
// Asserting only the first half would pass against a build that froze
// everything at construction, which would break every sized constructor;
// asserting only the second would pass against a build that froze nothing, which
// is the security regression. Both halves, one test.
func TestMemoryEnclave_MoveConstructedPagesAreReadOnly(t *testing.T) {
	if os.Getenv(frozenMarker) == "1" {
		frozenWriteChild(t)
		return
	}

	// The writable half runs in-process: it is supposed to succeed.
	sized, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	if err := sized.WithBytes(func(b []byte) error {
		b[0] = 0xFF // must not fault: this is the fill path
		return nil
	}); err != nil {
		t.Fatalf("filling a sized enclave: %v", err)
	}
	if !sized.EqualTo(append([]byte{0xFF}, make([]byte, 31)...)) {
		t.Error("the write into a sized enclave did not take")
	}
	sized.Destroy()

	// The read-only half kills the process when it works, so it needs a child.
	out, cerr := runTestChild(t, "TestMemoryEnclave_MoveConstructedPagesAreReadOnly", frozenMarker, "1")
	requireChildFaulted(t, out, cerr, frozenArmed, frozenSurvived,
		"a write through a move-constructed enclave (its pages are not frozen)")
}

func frozenWriteChild(t *testing.T) {
	t.Helper()

	e, err := NewMemoryEnclave([]byte("private-key-material"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}

	view, err := e.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	fmt.Println(frozenArmed)

	// The write the freeze exists to stop.
	view[0] = 0xFF

	fmt.Println(frozenSurvived)
	e.Destroy()
}

const (
	// copyFrozenMarker selects the child half of the copy-constructor frozen
	// test. It is a separate child from frozenMarker's because the write under
	// test kills the process: one child can only ever demonstrate one of them.
	copyFrozenMarker = "GO_ENCLAVE_COPY_FROZEN_WRITE"

	// copyFrozenArmed is printed by the child immediately before the store,
	// for the reason given on guardArmed.
	copyFrozenArmed = "copy-constructed and opened; writing through the view now"

	// copyFrozenSurvived is printed by the child if a write through a
	// copy-constructed enclave's borrow RETURNED. Seeing it is the failure.
	copyFrozenSurvived = "wrote through a copy-constructed enclave and lived"
)

// TestMemoryEnclave_CopyConstructedPagesAreReadOnly asserts the freeze for the
// copy constructor against the only oracle that cannot be faked: the fault
// itself.
//
// NewMemoryEnclaveCopy documents its result as frozen, and the in-process test
// beside it (TestNewMemoryEnclaveCopy_PagesAreFrozen) reads the mapping's own
// protection flag — which is a report about what the code believes, not about
// what the MMU enforces. A build that set the flag without issuing the mprotect
// would satisfy it and still let a stray write through a retained Open slice
// corrupt key material in silence. The flag test fails loudly and locates the
// bug; this one proves the page permission is real.
//
// The write is in a child because succeeding at it is what kills the process.
func TestMemoryEnclave_CopyConstructedPagesAreReadOnly(t *testing.T) {
	if os.Getenv(copyFrozenMarker) == "1" {
		copyFrozenWriteChild(t)
		return
	}

	out, cerr := runTestChild(t, "TestMemoryEnclave_CopyConstructedPagesAreReadOnly", copyFrozenMarker, "1")
	requireChildFaulted(t, out, cerr, copyFrozenArmed, copyFrozenSurvived,
		"a write through a copy-constructed enclave (its pages are not frozen)")
}

func copyFrozenWriteChild(t *testing.T) {
	t.Helper()

	src := []byte("private-key-material")
	e, err := NewMemoryEnclaveCopy(src)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}

	// The source is deliberately still live and still holds the material — that
	// is the whole point of this constructor — so a write through it must NOT
	// be what faults. Only the view into the enclave may.
	src[0] = 0xFE

	view, err := e.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	fmt.Println(copyFrozenArmed)

	// The write the freeze exists to stop.
	view[0] = 0xFF

	fmt.Println(copyFrozenSurvived)
	e.Destroy()
}

const (
	// corruptMarker selects the child half of the corrupted-Destroy test.
	corruptMarker = "GO_ENCLAVE_DESTROY_CORRUPT"

	// destroyPanicked is printed by the child from inside the recover, so its
	// presence is proof that Destroy panicked rather than returning quietly.
	destroyPanicked = "Destroy panicked with ErrEnclaveCorrupted"

	// destroySurvived is printed if Destroy RETURNED on a corrupted enclave.
	// Seeing it is the failure: a detected overflow was swallowed.
	destroySurvived = "Destroy returned on a corrupted enclave"
)

// TestMemoryEnclave_DestroyPanicsOnCorruption covers the one policy decision in
// this package that hands a caller something other than an error, and the
// ordering that goes with it.
//
// A failed canary means memory the enclave did not own was written. There is no
// error return on Destroy to report it through, and there is no state a caller
// could sensibly act on — the state it would act on is the state that is wrong —
// so Destroy panics. What it must do FIRST is finish cleaning up: wipe the
// material, unmap the pages, and return the Allocator reservation. Otherwise one
// detected overflow permanently shrinks a budget that outlives the enclave.
//
// The child asserts exactly that ordering from inside a recover, which is also
// what proves the panic happened at all.
func TestMemoryEnclave_DestroyPanicsOnCorruption(t *testing.T) {
	if os.Getenv(corruptMarker) == "1" {
		destroyCorruptChild(t)
		return
	}

	out, err := runTestChild(t, "TestMemoryEnclave_DestroyPanicsOnCorruption", corruptMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if strings.Contains(out, destroySurvived) {
		t.Fatalf("Destroy swallowed a detected corruption:\n%s", out)
	}
	if !strings.Contains(out, destroyPanicked) {
		t.Fatalf("subprocess did not confirm the panic:\n%s", out)
	}
	// The reservation must have come back before the panic unwound.
	if !strings.Contains(out, "inuse=0") {
		t.Fatalf("the Allocator reservation was not released before the panic:\n%s", out)
	}
}

func destroyCorruptChild(t *testing.T) {
	t.Helper()

	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	// A SIZED enclave, not a move-constructed one: NewMemoryEnclave freezes its
	// region read-only, so the write below would fault instead of corrupting —
	// which is the freeze doing its job, and is why this hazard is documented as
	// specific to sized enclaves in the first place.
	e, err := a.NewSized(64)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}
	if err := e.WithBytes(func(b []byte) error {
		copy(b, bytes.Repeat([]byte{0xA5}, len(b)))
		return nil
	}); err != nil {
		t.Fatalf("fill: %v", err)
	}
	if a.InUse() == 0 {
		t.Fatal("nothing was reserved; the test would be vacuous")
	}
	if len(e.m.canary) == 0 {
		t.Fatal("no canary slack for this size; the test would be vacuous")
	}

	// Exactly what a buffer underflow through a retained slice would do.
	e.m.canary[0] ^= 0xFF

	defer func() {
		r := recover()
		if r == nil {
			fmt.Println(destroySurvived)
			return
		}
		err, ok := r.(error)
		if !ok || !errors.Is(err, ErrEnclaveCorrupted) {
			fmt.Printf("Destroy panicked with the wrong value: %v\n", r)
			return
		}
		// Printed from inside the recover, so reaching this line is itself the
		// evidence that Destroy panicked. inuse is the ordering assertion.
		fmt.Printf("%s inuse=%d\n", destroyPanicked, a.InUse())
	}()

	e.Destroy()
}

// TestExcludeFromCoreDump_ReportsRefusal closes the one gap I had reported as
// unverifiable: that the per-mapping core-dump exclusion's error is CHECKED and
// not merely attempted.
//
// The angle is reviewer-enclave-9's (phase-1 finding A1/M5a). I had concluded no
// behavioral test could distinguish "checked" from "swallowed", because madvise
// succeeds in every environment this suite reaches — which is true of the
// mappings this package makes, and not true in general. madvise refuses an
// UNALIGNED address with EINVAL, so the failure can be induced with no
// production seam at all, the same lever the release-path tests use for mprotect.
//
// It matters because this is the only core-dump control here that is verified at
// all: the process-wide RLIMIT_CORE hardening is best effort. (Before #86 the
// mapping layer, memcall, also issued this madvise inside its Lock and
// discarded the result; nothing issues it unchecked now.) A silent no-op here would leave enclave pages eligible for a core file
// while the documentation said otherwise.
//
// It kills a mutant that makes excludeFromCoreDump itself return nil; a
// mutant that swallows the error at the call site in newMapping is killed by
// TestNewMapping_EveryConstructionStepRollsBack through the excludeCoreDump
// seam.
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

	// A page-aligned region is what every enclave actually passes, so this half
	// keeps the test honest: if madvise were refused here the assertion below
	// would pass for the wrong reason.
	if err := excludeFromCoreDump(region); err != nil {
		t.Fatalf("excludeFromCoreDump on an aligned region: %v", err)
	}

	// mmap guarantees a page-aligned base, so base+1 is guaranteed unaligned,
	// and madvise on an unaligned address is EINVAL by definition.
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
//
// This is the assertion #12 asks for and the reason the test is not merely
// "an error came back": the defect it guards against is material left RESIDENT,
// so the test has to establish that the pages are gone, not that a function
// returned. Reading /proc/self/maps does that without dereferencing an address
// that may or may not still be mapped -- touching it to find out would either
// succeed silently or kill the test process, and neither is an assertion.
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

// TestFrozenReleaseUnmapsWhenMprotectIsDenied is the regression for #12.
//
// A frozen enclave skips wipeAndVerify's early wipe -- its pages are read-only,
// so there is nothing it may write -- and can only be cleared through the
// release mprotect that makes the region writable again. Under a PERMANENT
// denial of that mprotect the old code returned an error and kept the mapping,
// leaving the secret resident in locked memory for the process lifetime.
//
// The fix hands the pages back with a bare munmap instead. This asserts the
// pages are actually GONE, and that the outcome is reported rather than passed
// off as an ordinary release.
func TestFrozenReleaseUnmapsWhenMprotectIsDenied(t *testing.T) {
	secret := []byte("material that must not stay resident")

	// newMemoryEnclave, NOT NewMemoryEnclave: this test drives m.release()
	// directly rather than Destroy(), and Destroy is what deregisters. The
	// exported constructor publishes to the shutdown ledger, so using it here
	// leaves a live entry behind and every WipeAll test in the package then
	// counts it -- measured, on the first version of this file.
	e, err := newMemoryEnclave(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("newMemoryEnclave: %v", err)
	}

	// The mapping is frozen by this constructor; if that ever stops being true
	// the test is no longer exercising the case it exists for.
	if e.m.mutable {
		t.Fatal("enclave is not frozen, so this test would pass without " +
			"covering the frozen path #12 is about")
	}

	addr := uintptr(unsafe.Pointer(&e.m.memory[0]))
	if !mappedAt(t, addr) {
		t.Fatal("the region is not mapped before release, so the assertion " +
			"after it would be vacuous")
	}

	denied := errors.New("mprotect denied by policy")
	previous := protectMemory
	t.Cleanup(func() { protectMemory = previous })
	protectMemory = func([]byte, protection) error { return denied }

	rerr := e.m.release()

	if !errors.Is(rerr, ErrReleasedWithoutWipe) {
		t.Fatalf("release = %v, want ErrReleasedWithoutWipe: a denied mprotect "+
			"on a frozen enclave must fall back to unmapping, and must say so", rerr)
	}
	if !errors.Is(rerr, denied) {
		t.Errorf("release = %v, want the underlying mprotect refusal reachable "+
			"through errors.Is; an operator needs to know what denied it", rerr)
	}

	// The point of the whole exercise.
	if mappedAt(t, addr) {
		t.Fatal("the region is STILL MAPPED after release: the material is " +
			"resident in locked memory for the process lifetime, which is " +
			"exactly the defect #12 reports")
	}

	if e.m.memory != nil || e.m.data != nil || e.m.inner != nil {
		t.Error("the mapping kept its slices after the pages were unmapped; a " +
			"reader would be looking at memory the kernel has taken back")
	}
}

// TestFrozenReleaseKeepsTheMappingWhenTheBypassAlsoFails pins the other half:
// when the fallback cannot run either, nothing is dropped.
//
// Losing the handle there would strand a region that is still mapped, possibly
// still locked and possibly still holding material, with no way to retry -- and
// would tell an Allocator those bytes are free while the kernel still holds them.
func TestFrozenReleaseKeepsTheMappingWhenTheBypassAlsoFails(t *testing.T) {
	e, err := newMemoryEnclave([]byte("material"))
	if err != nil {
		t.Fatalf("newMemoryEnclave: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	denied := errors.New("mprotect denied by policy")
	prevProtect := protectMemory
	prevUnmap := unmapMemory
	t.Cleanup(func() { protectMemory, unmapMemory = prevProtect, prevUnmap })
	protectMemory = func([]byte, protection) error { return denied }
	unmapMemory = func([]byte) error { return errors.New("munmap denied too") }

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

// TestKeptMappingReadsAsDestroyedOnceWiped is the regression for #13.
//
// When the wipe succeeded but the munlock or munmap after it was refused, the
// mapping is deliberately KEPT so Destroy can be retried. Before this it then
// read as an ordinary live enclave: IsAlive true, a non-zero Size, and Open
// handing back zeroes from a region whose guard pages the release path had
// already left READ-WRITE. A caller that recovers from Destroy's panic and reads
// rather than re-destroying would derive from an all-zero secret with the guards
// off, and nothing would say so.
func TestKeptMappingReadsAsDestroyedOnceWiped(t *testing.T) {
	e, err := newMemoryEnclave([]byte("material that is about to be wiped"))
	if err != nil {
		t.Fatalf("newMemoryEnclave: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	// wipeAndVerify is driven directly rather than through release() because
	// this test is about the state release() LEAVES BEHIND when the munlock or
	// munmap after a successful wipe is refused: material gone, pages still
	// held. Calling the step that produces that state is the shortest honest
	// way to reach it, and needs no syscall stub at all.
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
	if _, err := e.Open(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open = %v, want ErrEnclaveDestroyed: it would otherwise hand "+
			"back zeroes from a region whose guards are already read-write", err)
	}
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("WithBytes = %v, want ErrEnclaveDestroyed", err)
	}
	// Both comparison spellings go through the same withLocked path, and both
	// are asserted: EqualTo's bare false is indistinguishable from an ordinary
	// mismatch, so on its own it would pass against an implementation that
	// compared the caller's bytes with a region of zeroes and simply found them
	// different. EqualToErr is what shows the comparison did not RUN.
	if e.EqualTo([]byte("anything")) {
		t.Error("EqualTo reported a match against wiped memory")
	}
	if _, err := e.EqualToErr([]byte("anything")); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("EqualToErr = %v, want ErrEnclaveDestroyed: there is no "+
			"material left, so the comparison could not have run", err)
	}
}

// TestReleaseNeverUnmapsMaterialItCouldNotWipe kills mutant M12 from #14.
//
// release()'s wipe guard is what stops it carrying on to the ordinary unlock and
// unmap of a region that was never wiped, as if the wipe had happened. Deleting
// that guard left the whole suite green, so the property was unpinned: nothing
// established that a refused wipe diverts the release rather than merely being
// reported alongside it.
//
// The assertions are on the SYSCALLS as well as the error. Since #86 the
// fallback and the ordinary teardown share one unmap seam, so counting unmaps
// alone no longer separates them; what does is that the fallback never
// unlocks -- munmap drops the lock with the mapping -- and that its error
// carries the mprotect denial that diverted it.
func TestReleaseNeverUnmapsMaterialItCouldNotWipe(t *testing.T) {
	e, err := newMemoryEnclave([]byte("material that must not be handed back unwiped"))
	if err != nil {
		t.Fatalf("newMemoryEnclave: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	denied := errors.New("mprotect denied by policy")
	prevProtect, prevUnmap := protectMemory, unmapMemory
	t.Cleanup(func() { protectMemory, unmapMemory = prevProtect, prevUnmap })

	prevUnlock := unlockMemory
	t.Cleanup(func() { unlockMemory = prevUnlock })

	unmaps, unlocks := 0, 0
	protectMemory = func([]byte, protection) error { return denied }
	unlockMemory = func(b []byte) error {
		unlocks++
		return prevUnlock(b)
	}
	unmapMemory = func([]byte) error {
		unmaps++
		// Refuse, so the mapping is kept and the test can inspect it.
		return errors.New("munmap denied too")
	}

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

// TestKeptMutableMappingReadsAsDestroyedOnceWiped is the other branch of #13,
// found by the local Codex review of the first fix.
//
// wipeAndVerify destroys the material FIRST, before any syscall that can be
// refused -- but only for a mapping that is still mutable, which is what a
// [NewMemoryEnclaveSized] enclave is for its whole life. If the mprotect after
// that early wipe is then refused and release's unmap fallback is refused too,
// the mapping is KEPT with its material already zeroed. Recording the wipe only
// after the mprotect left exactly the state the flag exists to close, reached
// down the branch the frozen-path test cannot see: IsAlive true, a non-zero
// Size, and Open handing back zeroes.
func TestKeptMutableMappingReadsAsDestroyedOnceWiped(t *testing.T) {
	e, err := newMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("newMemoryEnclaveSized: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	// The premise. A sized enclave is never frozen, and if that ever changes
	// this test stops exercising the path it is named for.
	if !e.m.mutable {
		t.Fatal("the mapping is not mutable, so wipeAndVerify's early wipe " +
			"would not run and this test would cover nothing")
	}
	if err := e.WithBytes(func(b []byte) error { copy(b, "material in a fillable enclave"); return nil }); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}

	denied := errors.New("mprotect denied by policy")
	prevProtect, prevUnmap := protectMemory, unmapMemory
	t.Cleanup(func() { protectMemory, unmapMemory = prevProtect, prevUnmap })
	protectMemory = func([]byte, protection) error { return denied }
	unmapMemory = func([]byte) error { return errors.New("munmap denied too") }

	_ = e.m.release()

	// Both refusals landed, so the pages are still held -- which is the only
	// situation in which the questions below have anything to answer.
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
	if _, err := e.Open(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open = %v, want ErrEnclaveDestroyed: it would otherwise hand "+
			"back zeroes from a region whose guards are already read-write", err)
	}
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("WithBytes = %v, want ErrEnclaveDestroyed", err)
	}
	if _, err := e.EqualToErr([]byte("anything")); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("EqualToErr = %v, want ErrEnclaveDestroyed", err)
	}
}

// Process-memory sweep, shared by every test that has to prove material is not
// resident somewhere it should not be.
//
// There is exactly ONE copy. PR #16 (SealedEnclave) grew it inline and it was
// extracted so #18 could use it without a second copy drifting from the first;
// it lives here, with the other /proc instruments over this process's
// mappings, since #90 consolidated the test files onto the sources they cover.
//
// # Environment requirement (#90)
//
// It reads /proc/self/maps and /proc/self/mem. A process may always read its
// own, so this needs no privilege — but it does need a mounted /proc that is
// not filtered, and every test that sweeps FAILS without one rather than
// reporting a negative it could not have measured.
//
// The design is the corrected one, and the correction is worth keeping attached
// to the code: the first version skipped every kernel-NAMED mapping to avoid
// matching the test binary's own rodata, and the Go runtime NAMES its heap
// `[anon: Go: heap]`. Measured, that left one mapping swept and thirty skipped,
// so a plaintext copy retained on the heap forever went unnoticed by the one
// test written to catch it.
//
// The second lesson is the mirror of the first: an instrument can also SEE TOO
// MUCH — specifically, itself. The scan buffer holds copies of everything it
// reads, needle included, and an unwiped buffer becomes heap garbage a later
// sweep can find and misreport as a leak in the code under test. The first
// failure mode made the sweep blind; this one made it hallucinate. Both are
// documented at the code that fixes them.

// rangesOutside returns the matches that do not contain addr — that is, every
// copy of the needle other than the one the test is holding on purpose.
func rangesOutside(hits []string, addr uintptr) []string {
	var out []string
	for _, h := range hits {
		lo, hi, ok := parseSmapsHeader(h)
		if ok && addr >= lo && addr < hi {
			continue
		}
		out = append(out, h)
	}
	return out
}

// processMemoryFind returns the /proc/self/maps lines of every ANONYMOUS mapping
// that contains needle.
//
// File-backed mappings are excluded because the test binary's own rodata would
// match a literal needle in every run. Anonymous mappings are swept whether or
// not the kernel named them: the Go runtime labels its heap `[anon: Go: heap]`,
// and skipping named mappings is what made the first version of this sweep blind
// to the only place a leak could be.
func processMemoryFind(needle []byte) ([]string, error) {
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return nil, err
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return nil, err
	}
	defer mem.Close()

	const chunk = 1 << 20
	// Chunks overlap by len(needle)-1 so a needle straddling a boundary is not
	// missed — the failure mode of a fixed-window scan.
	overlap := len(needle) - 1
	buf := make([]byte, chunk+overlap)
	// THE SCAN BUFFER IS WIPED ON EVERY RETURN PATH, and this line is
	// load-bearing: without it the instrument PLANTS the very thing it looks
	// for. Scanning the needle's own (legitimate) mapping copies the needle
	// into buf — an ordinary heap allocation — and when buf becomes garbage
	// those bytes linger in the freed span until it is reused. A LATER sweep
	// then finds the EARLIER sweep's buffer and reports a heap residue that
	// never existed in the code under test. The same self-contamination shape
	// was independently hit and fixed in a parent-scans-child probe during
	// the PR #45 review, where the counts climbed 2->6->10 across scans.
	//
	// This buffer is ONE of two ways a sweep-based test was measured to smear
	// its own needle on PR #45. The other — a control copy in a
	// stack-allocatable local, stranded intact on the freed old stack when a
	// growth intervened between fill and wipe — cannot be fixed here or
	// anywhere, and retired that test's sweep formulation outright. (The
	// test in question left with the Decrypter/Signer adapter, split out to
	// issue #50; the forensics — hex-dump of the hit, addr2line on the
	// surrounding frames — are recorded there and on the PR #45 review.)
	// Tests that keep using this sweep must keep their needles out of plain
	// locals: generate into locked pages, hand copies only to callees that
	// take ownership and wipe (NewSealed), and compare from inside borrows.
	// The residency tests in this package hold to that; a new sweep-based
	// test that plants a bare heap or stack control copy will inherit the
	// flake.
	defer wipe(buf)

	var hits []string
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if !strings.HasPrefix(fields[1], "r") {
			continue
		}
		// File-backed only: a pathname starts with '/'. Kernel labels like
		// [anon: Go: heap], [stack] and [heap] are anonymous and ARE swept.
		if len(fields) > 5 && strings.HasPrefix(fields[5], "/") {
			continue
		}
		lo, hi, ok := parseSmapsHeader(line)
		if !ok || hi <= lo {
			continue
		}

		for off := lo; off < hi; {
			n := chunk
			if remaining := int(hi - off); remaining < n {
				n = remaining
			}
			read, rerr := mem.ReadAt(buf[:n], int64(off))
			if read > 0 && bytes.Contains(buf[:read], needle) {
				hits = append(hits, strings.TrimSpace(line))
				break
			}
			if rerr != nil {
				break
			}
			if read <= overlap {
				break
			}
			off += uintptr(read - overlap)
		}
	}
	return hits, nil
}

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
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/awnumar/memcall"
	"golang.org/x/sys/unix"
)

const (
	// guardMarker selects the child half of the guard-page test, and names which
	// guard it should write to.
	guardMarker = "GO_ENCLAVE_GUARD_WRITE"

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
			cmd := exec.Command(os.Args[0], "-test.run=^TestMapping_GuardPagesFault$", "-test.v")
			cmd.Env = append(os.Environ(), guardMarker+"="+guard)
			out, err := cmd.CombinedOutput()

			if strings.Contains(string(out), guardSurvived) {
				t.Fatalf("writing to the %sguard returned instead of faulting; the page is accessible:\n%s", guard, out)
			}
			if err == nil {
				t.Fatalf("the child exited cleanly after writing to the %sguard; it should have faulted:\n%s", guard, out)
			}
			if strings.Contains(string(out), "--- SKIP") {
				t.Skipf("child skipped:\n%s", out)
			}
		})
	}
}

func guardWriteChild(t *testing.T, guard string) {
	t.Helper()

	m, err := newMapping(32)
	if err != nil {
		t.Skipf("could not map: %v", err)
	}

	target := m.preguard
	if guard == "post" {
		target = m.postguard
	}

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

	cmd := exec.Command(os.Args[0], "-test.run=^TestMapping_FailedAllocationLeaksNothing$", "-test.v")
	cmd.Env = append(os.Environ(), leakMarker+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("subprocess could not inject the fault:\n%s", out)
	}
	for _, want := range []string{leakFaultArmed, leakNone} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
		}
	}
}

func allocLeakChild(t *testing.T) {
	t.Helper()

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Skipf("cannot read RLIMIT_MEMLOCK: %v", err)
	}
	// Zero locked memory allowed, so every mapping below gets as far as mmap
	// and then fails at mlock — which is the path under test.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 0, Max: original.Max}); err != nil {
		t.Skipf("cannot lower RLIMIT_MEMLOCK: %v", err)
	}

	lockedBefore, err := vmLckBytes()
	if err != nil {
		t.Skipf("cannot read VmLck: %v", err)
	}
	vmasBefore, err := vmaCount()
	if err != nil {
		t.Skipf("cannot read /proc/self/maps: %v", err)
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
		t.Skip("no mapping failed under a zero RLIMIT_MEMLOCK; the fault was not armed")
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
// enclave's pages must stay writable — that is what makes generate-in-place
// possible — so the same write succeeds there, and callers are told to finish
// the fill before sharing the enclave.
//
// Asserting only the first half would pass against a build that froze
// everything, which would break every sized constructor; asserting only the
// second would pass against a build that froze nothing, which is the security
// regression. Both halves, one test.
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
	cmd := exec.Command(os.Args[0], "-test.run=^TestMemoryEnclave_MoveConstructedPagesAreReadOnly$", "-test.v")
	cmd.Env = append(os.Environ(), frozenMarker+"=1")
	out, cerr := cmd.CombinedOutput()

	if strings.Contains(string(out), frozenSurvived) {
		t.Fatalf("a write through a move-constructed enclave returned instead of faulting; "+
			"its pages are not frozen:\n%s", out)
	}
	if cerr == nil {
		t.Fatalf("the child exited cleanly after writing to frozen pages; it should have faulted:\n%s", out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("child skipped:\n%s", out)
	}
}

func frozenWriteChild(t *testing.T) {
	t.Helper()

	e, err := NewMemoryEnclave([]byte("private-key-material"))
	if err != nil {
		t.Skipf("could not allocate: %v", err)
	}

	view, err := e.Open()
	if err != nil {
		t.Skipf("Open: %v", err)
	}

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

	cmd := exec.Command(os.Args[0], "-test.run=^TestMemoryEnclave_CopyConstructedPagesAreReadOnly$", "-test.v")
	cmd.Env = append(os.Environ(), copyFrozenMarker+"=1")
	out, cerr := cmd.CombinedOutput()

	if strings.Contains(string(out), copyFrozenSurvived) {
		t.Fatalf("a write through a copy-constructed enclave returned instead of faulting; "+
			"its pages are not frozen:\n%s", out)
	}
	if cerr == nil {
		t.Fatalf("the child exited cleanly after writing to frozen pages; it should have faulted:\n%s", out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("child skipped:\n%s", out)
	}
}

func copyFrozenWriteChild(t *testing.T) {
	t.Helper()

	src := []byte("private-key-material")
	e, err := NewMemoryEnclaveCopy(src)
	if err != nil {
		t.Skipf("could not allocate: %v", err)
	}

	// The source is deliberately still live and still holds the material — that
	// is the whole point of this constructor — so a write through it must NOT
	// be what faults. Only the view into the enclave may.
	src[0] = 0xFE

	view, err := e.Open()
	if err != nil {
		t.Skipf("Open: %v", err)
	}

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

	cmd := exec.Command(os.Args[0], "-test.run=^TestMemoryEnclave_DestroyPanicsOnCorruption$", "-test.v")
	cmd.Env = append(os.Environ(), corruptMarker+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), destroySurvived) {
		t.Fatalf("Destroy swallowed a detected corruption:\n%s", out)
	}
	if !strings.Contains(string(out), destroyPanicked) {
		t.Fatalf("subprocess did not confirm the panic:\n%s", out)
	}
	// The reservation must have come back before the panic unwound.
	if !strings.Contains(string(out), "inuse=0") {
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
		t.Skipf("could not allocate: %v", err)
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
// all: memcall's Lock attempts the same madvise and discards the result
// (memcall_unix.go:14), and the process-wide RLIMIT_CORE hardening is best
// effort. A silent no-op here would leave enclave pages eligible for a core file
// while the documentation said otherwise.
//
// Scope, stated precisely: this kills a mutant that makes excludeFromCoreDump
// itself return nil. It does NOT reach a mutant that swallows the error at the
// call site in newMapping, because newMapping always passes a page-aligned inner
// region, which cannot be made to fail. That call-site branch remains
// guaranteed by construction, and doc.go says so.
func TestExcludeFromCoreDump_ReportsRefusal(t *testing.T) {
	region, err := memcall.Alloc(2 * int(pageSize))
	if err != nil {
		t.Skipf("could not allocate the probe region: %v", err)
	}
	defer func() {
		if err := memcall.Free(region); err != nil {
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
	if err := excludeFromCoreDump(region[1:]); err == nil {
		t.Error("excludeFromCoreDump reported success on an unaligned region: " +
			"the kernel's refusal is being swallowed, and enclave pages could reach a core file")
	}
}

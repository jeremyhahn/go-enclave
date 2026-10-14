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
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// runTestChild re-executes this test binary running exactly the named test,
// with marker=value in its environment, and returns the child's combined
// output and exit error. Fault-injecting tests use it because their faults (an
// RLIMIT_MEMLOCK ceiling, a write that kills the process) are process-wide.
//
// A child that matched no test or skipped exits 0 without verifying anything,
// so both fail here.
func runTestChild(t *testing.T, test, marker, value string) (string, error) {
	t.Helper()
	return runTestChildWith(t, test, marker, value, nil)
}

// runTestChildWith is runTestChild with attr applied to the child, so a test
// can start it in new namespaces.
func runTestChildWith(t *testing.T, test, marker, value string, attr *syscall.SysProcAttr) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.v")
	cmd.Env = append(os.Environ(), marker+"="+value)
	cmd.SysProcAttr = attr
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "=== RUN   "+test) {
		t.Fatalf("the child process never ran %s (exit: %v), so it verified nothing:\n%s", test, err, out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Fatalf("the child process skipped instead of verifying anything:\n%s", out)
	}
	return string(out), err
}

// requireChildFaulted asserts that a child whose success condition is death
// died of the memory fault under test and of nothing else: it printed armed
// just before the faulting store, never printed survived, and exited with the
// runtime's fatal-fault status 2 and a "fatal error: fault" SIGSEGV report.
func requireChildFaulted(t *testing.T, out string, err error, armed, survived, what string) {
	t.Helper()
	if strings.Contains(out, survived) {
		t.Fatalf("%s returned instead of faulting:\n%s", what, out)
	}
	if !strings.Contains(out, armed) {
		t.Fatalf("the child never reached the faulting store, so whatever it died of proves nothing about %s:\n%s",
			what, out)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 {
		t.Fatalf("the child's exit was %v after %s, want the Go runtime's fatal-fault exit status 2:\n%s",
			err, what, out)
	}
	if !strings.Contains(out, "fatal error: fault") || !strings.Contains(out, "SIGSEGV") {
		t.Fatalf("the child died after %s, but not of a memory fault (no \"fatal error: fault\" / SIGSEGV "+
			"report from the runtime):\n%s", what, out)
	}
}

// injectMemlockCeiling makes RLIMIT_MEMLOCK bind for the calling goroutine and
// returns a setter for the soft limit.
//
// CAP_IPC_LOCK exempts a process from the limit, so it is dropped first.
// Capabilities are per thread, so the goroutine is pinned before they are
// touched and left pinned for the rest of the child. None of this needs
// privilege; a sandbox that filters getrlimit(2), setrlimit(2) or capset(2)
// fails these tests naming the refused call.
func injectMemlockCeiling(t *testing.T) (set func(cur uint64), original unix.Rlimit) {
	t.Helper()
	runtime.LockOSThread()

	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Fatalf("cannot read RLIMIT_MEMLOCK: %v (getrlimit(2) needs no privilege; this sandbox filters it)", err)
	}
	if testHoldsIPCLock(t) {
		if err := dropIPCLock(); err != nil {
			t.Fatalf("this process holds CAP_IPC_LOCK, which exempts it from RLIMIT_MEMLOCK, and dropping it "+
				"failed: %v. No locked-memory fault can be injected (dropping a capability needs no privilege; "+
				"this sandbox filters capset(2))", err)
		}
		if testHoldsIPCLock(t) {
			t.Fatal("CAP_IPC_LOCK is still effective after dropping it; RLIMIT_MEMLOCK cannot be made to bind")
		}
		// The soft limit now binds for the first time and may be anything,
		// zero included, since the capability hid it. Raise it to the suite's
		// requirement, which the hard limit must allow.
		if original.Cur != rlimInfinity && original.Cur < testMemlockRequirement {
			if original.Max != rlimInfinity && original.Max < testMemlockRequirement {
				t.Fatalf("this process held CAP_IPC_LOCK with a hard RLIMIT_MEMLOCK of %d; once the capability is "+
					"dropped for fault injection the suite needs at least %d bytes (raise the hard limit)",
					original.Max, testMemlockRequirement)
			}
			original.Cur = testMemlockRequirement
			if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
				t.Fatalf("raising the soft RLIMIT_MEMLOCK to the suite's requirement (%d) after dropping CAP_IPC_LOCK: %v",
					testMemlockRequirement, err)
			}
		}
	}
	set = func(cur uint64) {
		t.Helper()
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: cur, Max: original.Max}); err != nil {
			t.Fatalf("cannot set the soft RLIMIT_MEMLOCK to %d (hard %d): %v (a soft limit at or below the hard "+
				"one needs no privilege; this sandbox filters setrlimit(2))", cur, original.Max, err)
		}
	}
	return set, original
}

const (
	// subprocessMarker selects the child half of the fault-injection test below.
	subprocessMarker = "GO_ENCLAVE_LOCK_FAULT"

	// faultConfirmed is logged once the child has observed the injected
	// failure; the parent requires it so an unreached fault cannot pass.
	faultConfirmed = "locked-memory exhaustion reported as an error"

	// sourceWipeConfirmed is logged once the child has observed the caller's
	// slice wiped on the failing allocation path.
	sourceWipeConfirmed = "source slice wiped on the allocation-failure path"

	// copySourceIntactConfirmed is logged once the child has observed
	// NewMemoryCopy leave its source intact on the same failing path.
	copySourceIntactConfirmed = "source slice left intact on the allocation-failure path"
)

// TestNewMemory_LockedMemoryExhausted injects an RLIMIT_MEMLOCK fault
// and pins that an enclave that cannot be locked reports
// ErrLockedMemoryUnavailable instead of aborting, with the source wiped (and,
// for NewMemoryCopy, left intact). It runs in a subprocess because the
// fault is process-wide.
func TestNewMemory_LockedMemoryExhausted(t *testing.T) {
	if os.Getenv(subprocessMarker) == "1" {
		lockedMemoryExhaustionChild(t)
		return
	}

	out, err := runTestChild(t, "TestNewMemory_LockedMemoryExhausted", subprocessMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, faultConfirmed) {
		t.Fatalf("subprocess did not confirm the injected fault:\n%s", out)
	}
	if !strings.Contains(out, sourceWipeConfirmed) {
		t.Fatalf("subprocess did not confirm the source wipe:\n%s", out)
	}
	if !strings.Contains(out, copySourceIntactConfirmed) {
		t.Fatalf("subprocess did not confirm the copy constructor left its source intact:\n%s", out)
	}
}

func lockedMemoryExhaustionChild(t *testing.T) {
	t.Helper()

	// One page is below what a single guarded allocation needs, so the very
	// first lock attempt fails.
	setCeiling, _ := injectMemlockCeiling(t)
	setCeiling(uint64(os.Getpagesize()))

	var lastErr error
	var failedSource []byte
	for i := 0; i < 64; i++ {
		source := []byte(fmt.Sprintf("key-material-%d", i))
		e, err := newMemory(source)
		if err != nil {
			lastErr = err
			failedSource = source
			break
		}
		// Deliberately not destroyed: the point is to exhaust the ceiling.
		_ = e
	}

	if lastErr == nil {
		t.Fatal("expected an allocation failure under a one-page RLIMIT_MEMLOCK")
	}
	if !errors.Is(lastErr, ErrLockedMemoryUnavailable) {
		t.Fatalf("err = %v, want ErrLockedMemoryUnavailable", lastErr)
	}
	t.Log(faultConfirmed)

	// The constructor wipes its argument before every return, failure included.
	for i, b := range failedSource {
		if b != 0 {
			t.Fatalf("source[%d] = %#x after %v, want the slice wiped", i, b, lastErr)
		}
	}
	t.Log(sourceWipeConfirmed)

	// The mirror image: NewMemoryCopy leaves its source intact on every
	// path, this one included.
	copySrc := []byte("copy-material-under-a-ceiling")
	want := append([]byte(nil), copySrc...)

	if _, err := newMemoryCopy(copySrc); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("NewMemoryCopy err = %v, want ErrLockedMemoryUnavailable under the injected ceiling", err)
	}
	if !bytes.Equal(copySrc, want) {
		t.Fatalf("source = %q after a failed NewMemoryCopy, want it untouched (%q)", copySrc, want)
	}
	t.Log(copySourceIntactConfirmed)
}

const (
	// foreignMarker selects the child half of the foreign-failure test.
	foreignMarker = "GO_ENCLAVE_FOREIGN_FAILURE"

	// foreignFailed is logged once an unrelated allocation has failed under the
	// injected ceiling, so the test cannot pass vacuously.
	foreignFailed = "an unrelated allocation failed under the injected ceiling"

	// allocationRanDuringBorrow is logged once that failing allocation has
	// completed while a borrow was still in flight.
	allocationRanDuringBorrow = "the failing allocation completed while a borrow was live"

	// enclaveSurvived is logged once the unrelated enclave is confirmed alive
	// and still holding its material.
	enclaveSurvived = "the unrelated enclave survived intact"
)

// TestMemory_UnaffectedByForeignAllocationFailure pins that an
// allocation failure elsewhere in the process returns a typed error to its own
// caller and touches nothing else: an unrelated enclave stays alive and intact,
// and the failing allocation completes while a borrow is in flight. It runs in
// a subprocess because the fault is process-wide.
func TestMemory_UnaffectedByForeignAllocationFailure(t *testing.T) {
	if os.Getenv(foreignMarker) == "1" {
		foreignFailureChild(t)
		return
	}

	out, err := runTestChild(t, "TestMemory_UnaffectedByForeignAllocationFailure", foreignMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	for _, want := range []string{foreignFailed, allocationRanDuringBorrow, enclaveSurvived} {
		if !strings.Contains(out, want) {
			t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
		}
	}
}

func foreignFailureChild(t *testing.T) {
	t.Helper()

	const material = "server-private-key-material"

	// Allocated before the ceiling; nothing below touches it.
	a, err := newMemory([]byte(material))
	if err != nil {
		t.Fatalf("could not allocate the enclave under test before any ceiling was injected: %v", err)
	}

	// Lowering the soft limit does not unlock pages already locked, so a stays
	// intact; only subsequent allocations fail.
	setCeiling, _ := injectMemlockCeiling(t)
	setCeiling(uint64(os.Getpagesize()))

	// Park a borrow; the foreign allocation must not wait on it.
	borrowed := make(chan struct{})
	release := make(chan struct{})
	borrowErr := make(chan error, 1)
	go func() {
		borrowErr <- a.WithBytes(func(b []byte) error {
			close(borrowed)
			<-release
			// Read after the foreign failure has happened.
			if !bytes.Equal(b, []byte(material)) {
				return errors.New("borrowed material changed underneath the borrow")
			}
			return nil
		})
	}()
	<-borrowed

	// The borrow is parked; the failing allocation must complete on its own.
	var lastErr error
	for i := 0; i < 64; i++ {
		e, ferr := newMemory([]byte(fmt.Sprintf("foreign-material-%d", i)))
		if ferr != nil {
			lastErr = ferr
			break
		}
		// Deliberately not destroyed: the point is to reach the ceiling.
		_ = e
	}
	if lastErr == nil {
		t.Fatal("64 allocations succeeded under a one-page RLIMIT_MEMLOCK: the ceiling did not bind, no " +
			"fault was injected, and everything below would be vacuous")
	}
	if !errors.Is(lastErr, ErrLockedMemoryUnavailable) {
		t.Fatalf("foreign allocation err = %v, want ErrLockedMemoryUnavailable", lastErr)
	}
	t.Log(foreignFailed)

	// Reaching here means the allocation returned while the borrow was still
	// parked on a channel this goroutine has not closed.
	t.Log(allocationRanDuringBorrow)

	close(release)
	if err := <-borrowErr; err != nil {
		t.Fatalf("borrow: %v", err)
	}

	if !a.IsAlive() {
		t.Fatal("the unrelated enclave was destroyed by a foreign allocation failure")
	}
	if !holds(a, []byte(material)) {
		t.Fatal("the unrelated enclave's material did not survive a foreign allocation failure")
	}
	if a.Size() != len(material) {
		t.Fatalf("Size = %d after the foreign failure, want %d", a.Size(), len(material))
	}
	t.Log(enclaveSurvived)
}

const (
	// allocReleaseMarker selects the child half of the allocator
	// release-on-lock-failure test.
	allocReleaseMarker = "GO_ENCLAVE_ALLOC_RELEASE"

	// allocReleaseConfirmed is logged once a lock failure after successful
	// admission has returned the reservation to the allocator.
	allocReleaseConfirmed = "allocator released its reservation on a lock failure"
)

// TestAllocator_ReleasesReservationOnLockFailure injects an RLIMIT_MEMLOCK
// fault and pins that when admission succeeds but the lock fails,
// [Allocator.New] returns ErrLockedMemoryUnavailable and gives the reservation
// back. Only the allocator's counter can show this, since no enclave exists.
// It runs in a subprocess because the fault is process-wide.
func TestAllocator_ReleasesReservationOnLockFailure(t *testing.T) {
	if os.Getenv(allocReleaseMarker) == "1" {
		allocReleaseChild(t)
		return
	}

	out, err := runTestChild(t, "TestAllocator_ReleasesReservationOnLockFailure", allocReleaseMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, allocReleaseConfirmed) {
		t.Fatalf("subprocess did not confirm the reservation release:\n%s", out)
	}
}

func allocReleaseChild(t *testing.T) {
	t.Helper()

	// A budget large enough that only the OS lock can fail.
	a, err := newBudgetAllocator(1 << 20)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	setCeiling, _ := injectMemlockCeiling(t)
	setCeiling(uint64(os.Getpagesize()))

	// Allocations that succeed before the ceiling hold legitimate reservations
	// until Destroy; only the failed one's must be returned by the constructor.
	var survivors []*Memory
	var lastErr error
	for i := 0; i < 64; i++ {
		e, err := a.admitData([]byte(fmt.Sprintf("key-material-%d", i)))
		if err != nil {
			lastErr = err
			break
		}
		survivors = append(survivors, e)
	}

	if lastErr == nil {
		t.Fatal("expected a lock failure under a one-page RLIMIT_MEMLOCK")
	}
	if !errors.Is(lastErr, ErrLockedMemoryUnavailable) {
		t.Fatalf("err = %v, want ErrLockedMemoryUnavailable", lastErr)
	}

	for _, e := range survivors {
		e.Destroy()
	}

	// Anything left is the failed allocation's reservation, leaked.
	if got := a.InUse(); got != 0 {
		t.Fatalf("InUse = %d after releasing survivors, want 0 (failed allocation leaked its reservation)", got)
	}
	t.Log(allocReleaseConfirmed)
}

// TestNewMemorySized_MemoryIsLocked asks the kernel, via
// /proc/self/smaps, whether the region a sized enclave lends its filler is
// mlocked. An ordinary heap page is the control and must read 0 kB locked, so
// an mlockall'd process or a kernel without per-mapping Locked: figures fails
// rather than passing for the wrong reason.
func TestNewMemorySized_MemoryIsLocked(t *testing.T) {
	heap := make([]byte, os.Getpagesize())
	for i := range heap {
		heap[i] = 1 // fault the page in so it has a mapping to find
	}
	heapAddr, err := memscan.Addr(heap)
	if err != nil {
		t.Fatalf("heap address: %v", err)
	}
	heapKB, found, err := lockedKBForAddress(heapAddr)
	if err != nil {
		t.Fatalf("cannot read /proc/self/smaps: %v", err)
	}
	if !found {
		t.Fatalf("no smaps entry with a Locked: field covers ordinary heap memory at %#x: the kernel does not "+
			"report per-mapping locking, so the assertion below could not tell locked from unlocked", heapAddr)
	}
	if heapKB != 0 {
		t.Fatalf("ordinary heap memory reports %d kB locked: the process is mlockall'd, so every mapping reads "+
			"as locked and the assertion below would pass for the wrong reason", heapKB)
	}
	runtime.KeepAlive(heap)

	e, err := newMemorySized(64)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	defer e.Destroy()

	var addr uintptr
	if err := e.WithBytes(func(b []byte) error {
		var aerr error
		addr, aerr = memscan.Addr(b)
		return aerr
	}); err != nil {
		t.Fatalf("borrow: %v", err)
	}

	kb, found, err := lockedKBForAddress(addr)
	if err != nil {
		t.Fatalf("cannot read /proc/self/smaps: %v", err)
	}
	if !found {
		t.Fatalf("no smaps entry covers the borrowed region at %#x", addr)
	}
	if kb == 0 {
		t.Fatalf("the borrowed region at %#x reports 0 kB locked; a sized enclave's memory is not mlocked", addr)
	}
}

// lockedKBForAddress reports the Locked: figure of the /proc/self/smaps mapping
// that contains addr. found is false when no mapping covers addr, or when the
// kernel does not emit the field for it.
func lockedKBForAddress(addr uintptr) (kb int64, found bool, err error) {
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		return 0, false, err
	}
	defer f.Close()

	inRange := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if lo, hi, ok := memscan.ParseMapsHeader(line); ok {
			inRange = addr >= lo && addr < hi
			continue
		}
		if !inRange || !strings.HasPrefix(line, "Locked:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false, fmt.Errorf("malformed smaps line %q", line)
		}
		v, perr := strconv.ParseInt(fields[1], 10, 64)
		if perr != nil {
			return 0, false, fmt.Errorf("malformed smaps line %q: %w", line, perr)
		}
		return v, true, nil
	}
	return 0, false, sc.Err()
}

const (
	// sizedAdmissionMarker selects the child half of the admission-ordering test.
	sizedAdmissionMarker = "GO_ENCLAVE_SIZED_ADMISSION"

	// sizedRefusalConfirmed is logged once an over-budget NewSized has been
	// refused by admission while the locked-memory ceiling is exhausted.
	sizedRefusalConfirmed = "over-budget NewSized was refused by admission, not by the kernel"

	// sizedFaultArmed is logged once the same allocation, unadmitted, has been
	// refused by the kernel, proving the ceiling was live.
	sizedFaultArmed = "the injected ceiling was live: the same allocation, unadmitted, was refused by the kernel"

	// sizedNoCollateral is logged once an unrelated enclave has survived both
	// refusals.
	sizedNoCollateral = "an unrelated enclave survived both refusals intact"

	// sizedReservationReleased is logged once a lock failure after admission
	// has returned the reservation to the allocator.
	sizedReservationReleased = "NewSized released its reservation on a lock failure"
)

// TestAllocator_NewSized_RefusalNeverAttemptsMapping pins that
// [Allocator.NewSized] admission decides before any memory is mapped:
// ErrBudgetExhausted comes only from admission and ErrLockedMemoryUnavailable
// only from the kernel, so the sentinel says which layer refused. An unrelated
// canary enclave must survive both refusals. It runs in a subprocess because
// the fault is process-wide.
func TestAllocator_NewSized_RefusalNeverAttemptsMapping(t *testing.T) {
	if os.Getenv(sizedAdmissionMarker) == "1" {
		sizedAdmissionChild(t)
		return
	}

	out, err := runTestChild(t, "TestAllocator_NewSized_RefusalNeverAttemptsMapping", sizedAdmissionMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	for _, want := range []string{sizedRefusalConfirmed, sizedFaultArmed, sizedNoCollateral, sizedReservationReleased} {
		if !strings.Contains(out, want) {
			t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
		}
	}
}

func sizedAdmissionChild(t *testing.T) {
	t.Helper()

	const material = "canary-key-material"

	// Allocated before the ceiling.
	canary, err := newMemory([]byte(material))
	if err != nil {
		t.Fatalf("could not allocate the canary enclave before any ceiling was injected: %v", err)
	}

	// A budget far below the request, so admission refuses.
	a, err := newBudgetAllocator(16)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// Lowering the soft limit does not unlock pages already locked.
	setCeiling, _ := injectMemlockCeiling(t)
	setCeiling(uint64(os.Getpagesize()))

	const request = 4096

	e, err := a.admitSized(request)
	if e != nil {
		t.Fatal("over-budget NewSized returned a non-nil enclave")
	}
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	if errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatal("the request reached the mapping layer; admission did not decide first")
	}
	if a.InUse() != 0 {
		t.Fatalf("InUse = %d after the refusal, want 0", a.InUse())
	}
	t.Log(sizedRefusalConfirmed)

	// Non-vacuity: the same allocation without admission must be refused by
	// the kernel, showing the ceiling was live.
	if _, err := newMemorySized(request); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("unadmitted NewMemorySized err = %v, want ErrLockedMemoryUnavailable; "+
			"the ceiling was not live and the refusal above proves nothing", err)
	}
	t.Log(sizedFaultArmed)

	// Neither refusal may touch anything else.
	if !canary.IsAlive() {
		t.Fatal("an unrelated enclave died during a refusal")
	}
	if !holds(canary, []byte(material)) {
		t.Fatal("the canary's material did not survive the refusals")
	}
	t.Log(sizedNoCollateral)

	// An admitted sized allocation the OS then refuses must give its
	// reservation back; only the counter can show it.
	big, err := newBudgetAllocator(1 << 24)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if _, err := big.NewSized(request); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("admitted NewSized err = %v, want ErrLockedMemoryUnavailable", err)
	}
	if got := big.InUse(); got != 0 {
		t.Fatalf("InUse = %d after a lock failure, want 0 (the failed allocation leaked its reservation)", got)
	}
	t.Log(sizedReservationReleased)
}

const (
	// sealedMarker selects the child half of the frozen-sized-enclave test.
	sealedMarker = "GO_ENCLAVE_SEALED_WRITE"

	// sealedFroze is printed once Freeze has returned nil, just before the
	// write, so a child that died earlier cannot pass.
	sealedFroze = "Freeze returned nil; writing through the retained slice now"

	// sealedSurvived is printed only if that write returned: the pages were not
	// protected.
	sealedSurvived = "wrote through a frozen sized enclave and lived"
)

// TestMemory_FrozenSizedPagesFault pins by execution that a write
// through a retained slice faults after Freeze. The unfrozen write runs
// in-process as the control and must succeed; the frozen write runs in a child,
// which must die of an unrecoverable fault since the page is read-only and
// outside the Go heap.
func TestMemory_FrozenSizedPagesFault(t *testing.T) {
	if os.Getenv(sealedMarker) == "1" {
		sealedWriteChild(t)
		return
	}

	// Control: unfrozen, the same write succeeds. This is the fill path.
	unfrozen, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	view := unfrozen.m.data // a slice no lock covers, as a careless caller would keep
	view[0] = 0xFF          // must not fault: nothing has frozen these pages
	if !holds(unfrozen, append([]byte{0xFF}, make([]byte, 31)...)) {
		t.Error("the write into an unfrozen sized enclave did not take")
	}
	unfrozen.Destroy()

	out, cerr := runTestChild(t, "TestMemory_FrozenSizedPagesFault", sealedMarker, "1")
	requireChildFaulted(t, out, cerr, sealedFroze, sealedSurvived,
		"a write through a frozen sized enclave (Freeze did not protect the pages)")
}

func sealedWriteChild(t *testing.T) {
	t.Helper()

	e, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}

	// Retain the slice past the fill, the mistake Freeze makes loud.
	view := e.m.data // a slice no lock covers, as a careless caller would keep
	copy(view, []byte("0123456789abcdef0123456789abcdef"))

	if err := e.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	fmt.Println(sealedFroze)

	// The write the freeze exists to stop.
	view[0] = 0xFF

	fmt.Println(sealedSurvived)
	e.Destroy()
}

// TestMemory_FrozenDestroyFallsBackToUnmap pins the unmap fallback for a
// frozen sized enclave whose release mprotect is denied: Destroy returns
// ErrReleasedWithoutWipe, the pages leave the process's mappings, the Allocator
// reservation is returned, and the kernel's VmLck does not grow.
func TestMemory_FrozenDestroyFallsBackToUnmap(t *testing.T) {
	a, err := newBudgetAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	lockedBefore, err := vmLckBytes()
	if err != nil {
		t.Fatalf("cannot read VmLck: %v", err)
	}

	e, err := a.admitSized(64)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}
	if err := e.WithBytes(func(b []byte) error {
		copy(b, bytes.Repeat([]byte{0x7E}, len(b)))
		return nil
	}); err != nil {
		t.Fatalf("filling the enclave: %v", err)
	}
	if err := e.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	if e.m.mutable {
		t.Fatal("the enclave is not frozen, so this test would not reach the path it exists for")
	}

	addr := uintptr(unsafe.Pointer(&e.m.memory[0]))
	if !mappedAt(t, addr) {
		t.Fatal("the region is not mapped before the teardown; the assertion after it would be vacuous")
	}
	if reserved := a.InUse(); reserved == 0 {
		t.Fatal("nothing was reserved; the budget half of this test would be vacuous")
	}

	denied := errors.New("mprotect denied by policy")
	swapSeam(t, &protectMemory, func([]byte, protection) error { return denied })

	derr := e.Destroy()

	if !errors.Is(derr, ErrReleasedWithoutWipe) {
		t.Fatalf("Destroy = %v, want ErrReleasedWithoutWipe: a frozen sized enclave whose release "+
			"mprotect is denied must take the unmap fallback and say so", derr)
	}
	if !errors.Is(derr, denied) {
		t.Errorf("Destroy = %v, want the underlying refusal reachable through errors.Is", derr)
	}
	if mappedAt(t, addr) {
		t.Fatal("the region is STILL MAPPED after the teardown: a frozen sized enclave's material " +
			"is resident in locked memory for the process lifetime")
	}
	if e.IsAlive() {
		t.Error("the enclave reports itself alive over memory the kernel has taken back")
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("the Allocator still holds %d bytes reserved; the pages went back, so the "+
			"reservation must have too", used)
	}

	// The kernel's own accounting: munmap must drop the mlock charge too.
	lockedAfter, err := vmLckBytes()
	if err != nil {
		t.Fatalf("cannot read VmLck: %v", err)
	}
	if lockedAfter > lockedBefore {
		t.Errorf("VmLck = %d after the fallback, was %d before the enclave existed: the unmap did not "+
			"return the locked charge", lockedAfter, lockedBefore)
	}
}

// TestMemory_FreezeIsWhatPutsMaterialOnTheFallbackPath pins the cost of
// freezing: under a denied mprotect an unfrozen enclave reaches the unmap
// fallback already zeroed, and so releases cleanly, while a frozen one reaches
// it with the material still resident and reports ErrReleasedWithoutWipe.
// Both arms are observed from inside the unmap seam.
func TestMemory_FreezeIsWhatPutsMaterialOnTheFallbackPath(t *testing.T) {
	material := bytes.Repeat([]byte{0x9D}, 64)

	for _, tc := range []struct {
		name         string
		freeze       bool
		wantResidual bool
	}{
		{name: "unfrozen: wiped before the denied mprotect", freeze: false, wantResidual: false},
		{name: "frozen: still resident when the fallback runs", freeze: true, wantResidual: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Unexported constructor: release runs without Destroy, so the
			// exported one would leak a ledger entry into every WipeAll test.
			e, err := unpublishedSized(len(material))
			if err != nil {
				t.Fatalf("NewMemorySized: %v", err)
			}
			copy(e.m.data, material)
			if tc.freeze {
				if err := e.Freeze(); err != nil {
					t.Fatalf("Freeze: %v", err)
				}
			}
			if e.m.mutable == tc.freeze {
				t.Fatalf("mutable = %v with freeze = %v; the case under test is not set up",
					e.m.mutable, tc.freeze)
			}

			// Judged in place inside the seam, while the pages are still
			// mapped; frozen pages are readable, and nothing is copied out.
			view := e.m.data
			var unmapRan, zeroed, isMaterial bool
			prevUnmap := unmapMemory
			swapSeam(t, &protectMemory, func([]byte, protection) error {
				return errors.New("mprotect denied by policy")
			})
			swapSeam(t, &unmapMemory, func(b []byte) error {
				unmapRan = true
				zeroed = memscan.AllZero(view)
				isMaterial = bytes.Equal(view, material)
				return prevUnmap(b)
			})

			// L1: only the frozen arm skipped the wipe, so only it reports one.
			rerr := e.m.release()
			if got := errors.Is(rerr, ErrReleasedWithoutWipe); got != tc.wantResidual {
				t.Fatalf("release = %v: matches ErrReleasedWithoutWipe = %v, want %v", rerr, got, tc.wantResidual)
			}
			if !tc.wantResidual && rerr != nil {
				t.Fatalf("release of a wiped region = %v, want nil: the pages are gone and so is the material", rerr)
			}
			if !unmapRan {
				t.Fatal("the unmap fallback never ran, so nothing was measured")
			}

			if residual := !zeroed; residual != tc.wantResidual {
				t.Errorf("material still resident at the unmap = %v, want %v", residual, tc.wantResidual)
			}
			if tc.wantResidual && !isMaterial {
				t.Error("the frozen arm reached the fallback with something other than the material")
			}
		})
	}
}

// TestDestroyReportsTheDeniedMprotect pins that Destroy returns, rather than
// panics on, a denied release mprotect: ErrReleasedWithoutWipe as an
// *UnwipedReleaseError carrying the raw refusal, disjoint from
// ErrLockedMemoryUnavailable.
func TestDestroyReportsTheDeniedMprotect(t *testing.T) {
	e, err := newMemory([]byte("material for the public teardown path"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}

	denied := errors.New("mprotect denied by policy")
	swapSeam(t, &protectMemory, func([]byte, protection) error { return denied })

	derr := e.Destroy()
	if !errors.Is(derr, ErrReleasedWithoutWipe) {
		t.Fatalf("Destroy = %v, want ErrReleasedWithoutWipe", derr)
	}
	// The pages are gone, so this must not read as "pages still held".
	if errors.Is(derr, ErrLockedMemoryUnavailable) {
		t.Errorf("Destroy = %v matches ErrLockedMemoryUnavailable too; an unwiped release must be distinguishable from pages still held", derr)
	}
	var ure *UnwipedReleaseError
	if !errors.As(derr, &ure) || !errors.Is(ure.Cause, denied) {
		t.Errorf("Destroy = %v: want an *UnwipedReleaseError whose Cause is the mprotect refusal", derr)
	}
	var lme *LockedMemoryError
	if errors.As(derr, &lme) {
		t.Errorf("Destroy = %v carries a *LockedMemoryError; the cause should be the raw refusal", derr)
	}
	if e.IsAlive() {
		t.Error("the enclave reports itself alive after Destroy")
	}

	// Idempotent, and a second call has nothing left to report.
	if derr := e.Destroy(); derr != nil {
		t.Errorf("second Destroy = %v, want nil", derr)
	}
}

// TestDestroyIsNilOnAnOrdinaryTeardown is the control for the test above.
func TestDestroyIsNilOnAnOrdinaryTeardown(t *testing.T) {
	e, err := newMemory([]byte("material"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	if derr := e.Destroy(); derr != nil {
		t.Fatalf("Destroy on a clean teardown = %v, want nil", derr)
	}
}

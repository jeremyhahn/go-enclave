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
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// runTestChild re-executes this test binary running exactly the named test,
// with marker=value in its environment, and returns the child's combined
// output and exit error. Every fault-injecting test in this package uses it,
// because the faults are process-wide — an RLIMIT_MEMLOCK ceiling, a write
// that kills the process — and must not bind the rest of the suite.
//
// It refuses the two ways a child can report nothing while looking like it
// reported something. A -test.run filter that matched no test exits 0 with
// "no tests to run", which every parent that only checks the exit status
// would read as a pass; and a child that skipped also exits 0. Neither is a
// verification, so both fail here, before the caller looks at the result
// (#90: no test in this repository may skip).
func runTestChild(t *testing.T, test, marker, value string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^"+test+"$", "-test.v")
	cmd.Env = append(os.Environ(), marker+"="+value)
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "=== RUN   "+test) {
		t.Fatalf("the child process never ran %s (exit: %v), so it verified nothing:\n%s", test, err, out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Fatalf("the child process skipped instead of verifying anything:\n%s", out)
	}
	return string(out), err
}

// requireChildFaulted asserts that a child whose success condition is DEATH
// died of the memory fault under test, and of nothing else.
//
// Exiting non-zero is not evidence on its own: a child that failed to
// allocate, panicked, or failed an assertion exits non-zero too, and every one
// of those would read as the fault the parent is looking for. So the child
// prints armed immediately before the faulting store, and the parent requires
// that line, the runtime's own report of an unrecoverable memory fault
// ("fatal error: fault" with SIGSEGV), the runtime's exit status for it (2),
// and the absence of survived — which the child prints only if the store
// returned.
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
// returns a setter for the soft limit. It is the fault injector every
// locked-memory exhaustion child uses.
//
// # Environment requirement (#90)
//
// Nothing privileged: reading RLIMIT_MEMLOCK and lowering one's own soft limit
// need no capability, and so does dropping one. What the injector cannot do is
// make the limit bind for a process the kernel exempts from it — one holding
// CAP_IPC_LOCK — so it drops that capability first. Capabilities are PER
// THREAD and the runtime moves goroutines between threads, so the goroutine is
// pinned before they are touched and left pinned: the child process ends with
// its test, and every allocation that must fail runs on this goroutine. A
// sandbox that filters getrlimit(2), setrlimit(2) or capset(2) cannot run these
// tests, and they FAIL there saying which call was refused — the unit-test
// runner (CI's Test job, the devcontainer) must not filter them.
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
		// With the capability gone the soft limit binds for the first time,
		// and TestMain admitted this process as unbounded BECAUSE of the
		// capability — so the soft value it started with may be anything,
		// zero included. "Restoring" that would reinstate a ceiling that only
		// ever looked harmless while the capability hid it. The usable
		// ceiling after the drop is the suite's stated requirement, which the
		// hard limit must allow.
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

	// faultConfirmed is logged by the child once it has actually observed the
	// injected failure. The parent requires it, so that a child which never
	// reached the fault cannot be mistaken for a child which verified the
	// behavior.
	faultConfirmed = "locked-memory exhaustion reported as an error"

	// sourceWipeConfirmed is logged by the child once it has observed that the
	// caller's slice was wiped on the failing allocation path. memguard moves
	// and wipes its source only after a successful allocation, so without an
	// explicit wipe the secret survives in the caller's memory on exactly this
	// path — the parent requires this line for the same reason it requires
	// faultConfirmed.
	sourceWipeConfirmed = "source slice wiped on the allocation-failure path"

	// copySourceIntactConfirmed is logged by the child once it has observed the
	// OPPOSITE contract holding for NewMemoryEnclaveCopy on the same failing
	// path. That constructor promises the source survives on EVERY path, and a
	// shared body plus a misplaced wipe would break it exactly here, where no
	// happy-path test looks.
	copySourceIntactConfirmed = "source slice left intact on the allocation-failure path"
)

// TestNewMemoryEnclave_LockedMemoryExhausted injects an RLIMIT_MEMLOCK fault
// and asserts that an enclave that cannot be locked reports
// ErrLockedMemoryUnavailable rather than aborting the process — memguard's own
// behavior on that path is to panic, which a foundational library must never
// inflict on its host.
//
// The fault has to be injected process-wide, and recovering from memguard's
// panic purges every live locked buffer, so this runs in a subprocess.
func TestNewMemoryEnclave_LockedMemoryExhausted(t *testing.T) {
	if os.Getenv(subprocessMarker) == "1" {
		lockedMemoryExhaustionChild(t)
		return
	}

	out, err := runTestChild(t, "TestNewMemoryEnclave_LockedMemoryExhausted", subprocessMarker, "1")
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
		e, err := NewMemoryEnclave(source)
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

	// The constructor takes ownership of its argument and promises to wipe it
	// before every return. Verify that holds on the failure path, where
	// memguard never got as far as moving the bytes out.
	for i, b := range failedSource {
		if b != 0 {
			t.Fatalf("source[%d] = %#x after %v, want the slice wiped", i, b, lastErr)
		}
	}
	t.Log(sourceWipeConfirmed)

	// The mirror image, under the same injected ceiling. NewMemoryEnclaveCopy
	// documents an intact source on every path including this one, and the
	// mapping failure is the path where the two constructors' contracts are
	// most easily confused: nothing was copied out, so the material is still in
	// the caller's slice either way, and only the wipe distinguishes them.
	copySrc := []byte("copy-material-under-a-ceiling")
	want := append([]byte(nil), copySrc...)

	if _, err := NewMemoryEnclaveCopy(copySrc); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("NewMemoryEnclaveCopy err = %v, want ErrLockedMemoryUnavailable under the injected ceiling", err)
	}
	if !bytes.Equal(copySrc, want) {
		t.Fatalf("source = %q after a failed NewMemoryEnclaveCopy, want it untouched (%q)", copySrc, want)
	}
	t.Log(copySourceIntactConfirmed)
}

const (
	// foreignMarker selects the child half of the foreign-failure test.
	foreignMarker = "GO_ENCLAVE_FOREIGN_FAILURE"

	// foreignFailed is logged by the child once an unrelated allocation has
	// actually failed under the injected ceiling. Without it the test would pass
	// vacuously on any run where the fault never bit.
	foreignFailed = "an unrelated allocation failed under the injected ceiling"

	// allocationRanDuringBorrow is logged once the child has seen that failing
	// allocation COMPLETE while a borrow was still in flight. Before
	// v0.3.0-alpha it could not: allocation took purgeMu exclusively and parked
	// until every borrow had returned.
	allocationRanDuringBorrow = "the failing allocation completed while a borrow was live"

	// enclaveSurvived is logged once the child has confirmed the unrelated
	// enclave is still alive and still holds its material. Before v0.3.0-alpha
	// it was destroyed: memguard purged every live buffer in the process before
	// panicking, and the most this package could do was hold the borrow safe
	// across it.
	enclaveSurvived = "the unrelated enclave survived intact"
)

// TestMemoryEnclave_UnaffectedByForeignAllocationFailure is the headline
// behavioral change of v0.3.0-alpha, and it replaces the test that used to
// live here.
//
// That test — BorrowSurvivesForeignAllocationFailure — asserted the best thing
// achievable while memguard owned the memory: an allocation failure ANYWHERE in
// the process purged and unmapped every live buffer, so the most go-enclave
// could promise was that an in-flight borrow was held safe across the purge by
// a process-wide lock. The enclave itself still died, and the lock is what made
// allocating inside a borrow deadlock.
//
// go-enclave now maps its own memory. There is no registry to purge, so a
// foreign failure is simply a failure: it returns a typed error to its own
// caller and touches nothing else. This test asserts the
// stronger property directly — the unrelated enclave is ALIVE and INTACT
// afterwards — and, because there is no lock any more, that the failing
// allocation ran to completion while a borrow was still in flight.
//
// It stays in a subprocess because the fault is injected process-wide.
func TestMemoryEnclave_UnaffectedByForeignAllocationFailure(t *testing.T) {
	if os.Getenv(foreignMarker) == "1" {
		foreignFailureChild(t)
		return
	}

	out, err := runTestChild(t, "TestMemoryEnclave_UnaffectedByForeignAllocationFailure", foreignMarker, "1")
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

	// Allocated while locked memory is still available. Nothing below ever
	// touches it; its survival is the whole point.
	a, err := NewMemoryEnclave([]byte(material))
	if err != nil {
		t.Fatalf("could not allocate the enclave under test before any ceiling was injected: %v", err)
	}

	// Lowering the soft limit does not unlock pages already locked, so a stays
	// intact; only subsequent allocations fail.
	setCeiling, _ := injectMemlockCeiling(t)
	setCeiling(uint64(os.Getpagesize()))

	// Park a borrow. On the old design this is what made the foreign allocation
	// wait; here it must not interact with it at all.
	borrowed := make(chan struct{})
	release := make(chan struct{})
	borrowErr := make(chan error, 1)
	go func() {
		borrowErr <- a.WithBytes(func(b []byte) error {
			close(borrowed)
			<-release
			// Read AFTER the foreign failure has happened. On the old design
			// these pages were unmapped by then and this faulted the process.
			if !bytes.Equal(b, []byte(material)) {
				return errors.New("borrowed material changed underneath the borrow")
			}
			return nil
		})
	}()
	<-borrowed

	// The borrow is live and parked. A failing allocation now has to complete
	// on its own — nothing waits for anything.
	var lastErr error
	for i := 0; i < 64; i++ {
		e, ferr := NewMemoryEnclave([]byte(fmt.Sprintf("foreign-material-%d", i)))
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

	// Reaching here at all is the second assertion: the allocation returned
	// while the borrow was still parked. Under the old process-wide lock this
	// line was unreachable — the allocation would be blocked on purgeMu until
	// the borrow released, and the borrow is waiting on a channel this
	// goroutine has not closed yet.
	t.Log(allocationRanDuringBorrow)

	close(release)
	if err := <-borrowErr; err != nil {
		t.Fatalf("borrow: %v", err)
	}

	if !a.IsAlive() {
		t.Fatal("the unrelated enclave was destroyed by a foreign allocation failure")
	}
	if !a.EqualTo([]byte(material)) {
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

	// allocReleaseConfirmed is logged by the child once it has observed that a
	// lock failure UNDER admission returned the reservation to the allocator —
	// admission having already succeeded, so the only way InUse returns to zero
	// is the constructor's own release-on-failure path.
	allocReleaseConfirmed = "allocator released its reservation on a lock failure"
)

// TestAllocator_ReleasesReservationOnLockFailure injects an RLIMIT_MEMLOCK
// fault and asserts that when admission SUCCEEDS but the underlying lock then
// fails, [Allocator.New] returns ErrLockedMemoryUnavailable AND returns the
// reservation, so a transient exhaustion does not permanently shrink the
// budget. This is the mutation killer for the release-on-construction-failure
// path in Allocator.New (`a.free.Add(charge)`): a behavioral check on the enclave
// cannot see it, because there is no enclave — only the allocator's counter
// records whether the reservation leaked.
//
// It runs in a subprocess for the same reason as the tests above: the fault is
// injected process-wide and recovering from memguard's panic purges every live
// locked buffer.
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

	// A budget far larger than anything we allocate, so admission always
	// passes and the ONLY failure comes from the OS lock, not the gate.
	a, err := NewAllocator(1 << 20)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	setCeiling, _ := injectMemlockCeiling(t)
	setCeiling(uint64(os.Getpagesize()))

	// Track successes so their reservations can be returned explicitly. An
	// allocation may succeed before the ceiling is reached; its reservation is
	// legitimate until Destroy. Only the FAILED allocation's reservation is
	// what this test is about, and the constructor must return it itself.
	var survivors []*MemoryEnclave
	var lastErr error
	for i := 0; i < 64; i++ {
		e, err := a.New([]byte(fmt.Sprintf("key-material-%d", i)))
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

	// Return every surviving reservation. Destroy runs the release hook even on
	// a buffer memguard already purged (buffer non-nil but dead), so this is
	// exact regardless of how many survived.
	for _, e := range survivors {
		e.Destroy()
	}

	// With survivors accounted for, anything left in the counter is the failed
	// allocation's reservation, leaked. The release-on-failure path
	// (`a.free.Add(charge)`) is the only thing that returns it; delete that line
	// and this assertion fails.
	if got := a.InUse(); got != 0 {
		t.Fatalf("InUse = %d after releasing survivors, want 0 (failed allocation leaked its reservation)", got)
	}
	t.Log(allocReleaseConfirmed)
}

// TestNewMemoryEnclaveSized_MemoryIsLocked asks the kernel whether the region a
// sized enclave hands to its filler is actually mlock'd, rather than trusting
// that memguard did what its documentation says.
//
// This is the half of the generate-in-place claim that
// TestNewMemoryEnclaveSized_FillsInPlace cannot make: that test proves the
// generator wrote into the enclave's own storage, and this one proves that
// storage is locked memory. A constructor that quietly fell back to an ordinary
// allocation would satisfy the first and fail here.
//
// The yardstick is an ordinary heap allocation, read from the same /proc file by
// the same parser, and it is established BEFORE the enclave exists — so a
// process that turned out to be mlockall'd, or a kernel that does not report the
// field, FAILS rather than passing for the wrong reason. The runner must be a
// real Linux kernel exposing /proc/self/smaps with per-mapping Locked: figures,
// and must not mlockall the test process (#90).
func TestNewMemoryEnclaveSized_MemoryIsLocked(t *testing.T) {
	heap := make([]byte, os.Getpagesize())
	for i := range heap {
		heap[i] = 1 // fault the page in so it has a mapping to find
	}
	heapAddr, err := sliceAddr(heap)
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

	e, err := NewMemoryEnclaveSized(64)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer e.Destroy()

	var addr uintptr
	if err := e.WithBytes(func(b []byte) error {
		var aerr error
		addr, aerr = sliceAddr(b)
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

// sliceAddr returns the address of a slice's first element. It goes through the
// fmt verb rather than unsafe so that a test asserting a memory property does
// not itself need the unsafe package.
func sliceAddr(b []byte) (uintptr, error) {
	var addr uint64
	if _, err := fmt.Sscanf(fmt.Sprintf("%p", b), "0x%x", &addr); err != nil {
		return 0, fmt.Errorf("parsing slice address: %w", err)
	}
	return uintptr(addr), nil
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
		if lo, hi, ok := parseSmapsHeader(line); ok {
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

// parseSmapsHeader recognizes an smaps mapping header ("7f0c…-7f0c… rw-p …")
// and returns its bounds. The per-mapping detail lines that follow it never
// parse as one, so this is what separates the two.
func parseSmapsHeader(line string) (lo, hi uintptr, ok bool) {
	first, _, cut := strings.Cut(line, " ")
	if !cut {
		return 0, 0, false
	}
	l, r, cut := strings.Cut(first, "-")
	if !cut {
		return 0, 0, false
	}
	lv, err := strconv.ParseUint(l, 16, 64)
	if err != nil {
		return 0, 0, false
	}
	rv, err := strconv.ParseUint(r, 16, 64)
	if err != nil {
		return 0, 0, false
	}
	return uintptr(lv), uintptr(rv), true
}

const (
	// sizedAdmissionMarker selects the child half of the admission-ordering test.
	sizedAdmissionMarker = "GO_ENCLAVE_SIZED_ADMISSION"

	// sizedRefusalConfirmed is logged by the child once an over-budget NewSized
	// has been refused as a BUDGET refusal with the process's locked-memory
	// ceiling already exhausted — the answer the mapping layer could not have
	// given, since under that ceiling it can only fail to lock.
	sizedRefusalConfirmed = "over-budget NewSized was refused by admission, not by the kernel"

	// sizedFaultArmed is logged by the child once it has shown the lock fault
	// was live during that refusal, by taking the same allocation unadmitted and
	// watching the kernel refuse it. Without this the test would pass vacuously
	// on any run where the injected ceiling never bit.
	sizedFaultArmed = "the injected ceiling was live: the same allocation, unadmitted, was refused by the kernel"

	// sizedNoCollateral is logged once the child has confirmed an unrelated
	// enclave survived BOTH refusals. Before v0.3.0-alpha the unadmitted one
	// destroyed it: memguard purged every live buffer in the process on its way
	// to reporting the failure.
	sizedNoCollateral = "an unrelated enclave survived both refusals intact"

	// sizedReservationReleased is logged by the child once it has observed that a
	// lock failure UNDER admission returned the reservation to the allocator.
	sizedReservationReleased = "NewSized released its reservation on a lock failure"
)

// TestAllocator_NewSized_RefusalNeverAttemptsMapping proves the ordering
// [Allocator.NewSized] promises: admission decides BEFORE any memory is mapped
// or locked.
//
// The discriminator is the sentinel, and under this design that is sound in a
// way it was not before v0.3.0-alpha. Back then a typed error proved nothing on
// its own — ErrLockedMemoryUnavailable came back from the far side of a
// process-wide purge, so the damage was already done and the test had to watch
// an unrelated canary enclave die to tell the two paths apart. There is no purge
// now: ErrBudgetExhausted can only come from admission and
// ErrLockedMemoryUnavailable only from the kernel refusing the lock, so which
// one arrives says which layer refused.
//
// The canary is still here, asserting the property that replaced it: it must
// survive BOTH refusals, including the unadmitted one that used to destroy it.
//
// It runs in a subprocess because the fault is injected process-wide.
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

	// Allocated while locked memory is still available, and never touched by
	// the allocator under test.
	canary, err := NewMemoryEnclave([]byte(material))
	if err != nil {
		t.Fatalf("could not allocate the canary enclave before any ceiling was injected: %v", err)
	}

	// A budget far below what is requested below, so admission is the only
	// thing that can refuse.
	a, err := NewAllocator(16)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// Lowering the soft limit does not unlock pages already locked, so the
	// canary stays intact; only subsequent allocations fail.
	setCeiling, _ := injectMemlockCeiling(t)
	setCeiling(uint64(os.Getpagesize()))

	const request = 4096

	e, err := a.NewSized(request)
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

	// Non-vacuity. The same allocation, taken without admission, must be
	// refused by the KERNEL under the ceiling that was already in force above —
	// which is what shows the ceiling was live and the different answer above
	// came from admission rather than from luck.
	if _, err := NewMemoryEnclaveSized(request); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("unadmitted NewMemoryEnclaveSized err = %v, want ErrLockedMemoryUnavailable; "+
			"the ceiling was not live and the refusal above proves nothing", err)
	}
	t.Log(sizedFaultArmed)

	// Neither refusal may touch anything else. The unadmitted one is the
	// interesting half: before v0.3.0-alpha it purged the process here and this
	// enclave came back dead.
	if !canary.IsAlive() {
		t.Fatal("an unrelated enclave died during a refusal")
	}
	if !canary.EqualTo([]byte(material)) {
		t.Fatal("the canary's material did not survive the refusals")
	}
	t.Log(sizedNoCollateral)

	// With the ceiling still in force, an ADMITTED sized allocation that the OS
	// then refuses must give its reservation back, so a transient exhaustion
	// does not shrink the budget permanently. There is no enclave to inspect —
	// only the counter records whether the release path ran, which makes this
	// the mutation killer for `a.free.Add(charge)` in NewSized.
	big, err := NewAllocator(1 << 24)
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

	// sealedFroze is printed by the child once Freeze has RETURNED NIL, before
	// the write. The parent requires it, because a child that died for any other
	// reason — a refused allocation, a failed fill, a panic in Freeze — exits
	// non-zero too, and without this marker every one of those would read as
	// proof of a fault the test never observed.
	sealedFroze = "Freeze returned nil; writing through the retained slice now"

	// sealedSurvived is printed by the child if that write RETURNED. Seeing it is
	// the failure this issue exists to close: the pages were not protected and a
	// stray write corrupts key material with nothing to announce it.
	sealedSurvived = "wrote through a frozen sized enclave and lived"
)

// TestMemoryEnclave_FrozenSizedPagesFault is the execution evidence for
// Freeze: the property is that a write through a retained slice FAULTS, and a
// property about faults is not established by asserting a bool that a
// bookkeeping bug could set on its own.
//
// The two halves have to run in different processes because they have different
// success conditions. The write BEFORE the freeze must return — that is the fill
// path, and an implementation that froze a sized enclave at construction would
// break every consumer of it — so it runs here, in-process. The write AFTER the
// freeze must kill the process: the fault is at a mapped-but-read-only address
// outside the Go heap, which the runtime reports as an unrecoverable fault
// rather than a catchable panic. So the child's evidence is inverted — it must
// die, and must not have printed the survival marker on its way.
//
// The in-process half is also the control in the strict sense: it is the same
// enclave shape, the same retained slice and the same store, differing only in
// whether Freeze ran. Without it a child that faulted for an unrelated reason
// would look like a pass.
func TestMemoryEnclave_FrozenSizedPagesFault(t *testing.T) {
	if os.Getenv(sealedMarker) == "1" {
		sealedWriteChild(t)
		return
	}

	// Control: unfrozen, the same write succeeds. This is the fill path.
	unfrozen, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	view, err := unfrozen.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	view[0] = 0xFF // must not fault: nothing has frozen these pages
	if !unfrozen.EqualTo(append([]byte{0xFF}, make([]byte, 31)...)) {
		t.Error("the write into an unfrozen sized enclave did not take")
	}
	unfrozen.Destroy()

	out, cerr := runTestChild(t, "TestMemoryEnclave_FrozenSizedPagesFault", sealedMarker, "1")
	requireChildFaulted(t, out, cerr, sealedFroze, sealedSurvived,
		"a write through a frozen sized enclave (Freeze did not protect the pages)")
}

func sealedWriteChild(t *testing.T) {
	t.Helper()

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}

	// Fill exactly as a consumer would, and retain the slice past the borrow,
	// which is the mistake the freeze is meant to make loud.
	view, err := e.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
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

// TestMemoryEnclave_FrozenDestroyFallsBackToUnmap is the interaction between
// this branch and #38, and it is the pairing that makes both changes matter.
//
// #38 gave the release path a bare-munmap fallback because a frozen enclave
// skips wipeAndVerify's early wipe — its pages are read-only, so there is
// nothing it may write — and a PERMANENTLY denied mprotect would otherwise leave
// the material resident in locked memory for the process lifetime. Until this
// branch, "frozen" and "built from existing material" were the same set. Freeze
// puts SIZED enclaves into it, so the fallback now has to cover a class of
// enclave it was never exercised against: one with an Allocator reservation
// behind it, frozen after construction rather than during it.
//
// Three things are asserted, and the middle one is the point: the condition is
// REPORTED through Destroy, the pages are actually GONE from the process's
// mappings, and the locked-memory accounting comes back — a fallback that
// unmapped without the kernel dropping the mlock charge would leak a locked page
// per teardown under a seccomp policy, which is exactly the environment where
// pages are scarcest.
func TestMemoryEnclave_FrozenDestroyFallsBackToUnmap(t *testing.T) {
	a, err := NewAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	lockedBefore, err := vmLckBytes()
	if err != nil {
		t.Fatalf("cannot read VmLck: %v", err)
	}

	e, err := a.NewSized(64)
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
	prev := protectMemory
	t.Cleanup(func() { protectMemory = prev })
	protectMemory = func([]byte, protection) error { return denied }

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

	// The kernel's own accounting, not this package's. munmap drops the mlock
	// charge with the mapping; if it did not, every teardown under a denying
	// policy would leak a page of the process's RLIMIT_MEMLOCK budget.
	lockedAfter, err := vmLckBytes()
	if err != nil {
		t.Fatalf("cannot read VmLck: %v", err)
	}
	if lockedAfter > lockedBefore {
		t.Errorf("VmLck = %d after the fallback, was %d before the enclave existed: the unmap did not "+
			"return the locked charge", lockedAfter, lockedBefore)
	}
}

// TestMemoryEnclave_FreezeIsWhatPutsMaterialOnTheFallbackPath measures the COST
// this branch's doc comment claims, instead of asserting it.
//
// The claim is that freezing moves the material's wipe behind a syscall that can
// be refused: wipeAndVerify overwrites the data BEFORE the mprotect while the
// region is still writable, and skips that early wipe exactly when the pages are
// read-only. So under a denied mprotect an unfrozen sized enclave reaches the
// fallback with its material already zeroed, and a frozen one reaches it with
// the material still there — which is why #38's fallback exists at all.
//
// Both halves run, because either alone proves nothing: if the frozen case did
// not carry live material the fallback would be unnecessary, and if the unfrozen
// case did too then the early wipe would not be doing anything. The observation
// is taken from inside the unmap seam, the one instant where the pages are still
// mapped and the decision has already been made.
func TestMemoryEnclave_FreezeIsWhatPutsMaterialOnTheFallbackPath(t *testing.T) {
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
			// Unexported: this test lets the release run without Destroy, and the
			// exported constructor would leave a live ledger entry behind for
			// every WipeAll test in the package to count.
			e, err := newMemoryEnclaveSized(len(material))
			if err != nil {
				t.Fatalf("newMemoryEnclaveSized: %v", err)
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

			// Judge the data region IN PLACE at the moment the fallback is
			// about to hand the pages back. Frozen pages are read-only, not
			// inaccessible, so this read is safe in both arms. Nothing is
			// copied out: the verdicts are taken inside the seam, while the
			// pages are still mapped, so the material never reaches the heap
			// (#90; security-review.md §6).
			view := e.m.data
			var unmapRan, zeroed, isMaterial bool
			prevProtect, prevUnmap := protectMemory, unmapMemory
			t.Cleanup(func() { protectMemory, unmapMemory = prevProtect, prevUnmap })
			protectMemory = func([]byte, protection) error {
				return errors.New("mprotect denied by policy")
			}
			unmapMemory = func(b []byte) error {
				unmapRan = true
				zeroed = allZero(view)
				isMaterial = bytes.Equal(view, material)
				return prevUnmap(b)
			}

			if rerr := e.m.release(); !errors.Is(rerr, ErrReleasedWithoutWipe) {
				t.Fatalf("release = %v, want ErrReleasedWithoutWipe", rerr)
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

// TestDestroyReportsTheDeniedMprotect pins the public path.
//
// Destroy correctly does NOT panic on an unwiped release -- nothing was corrupted
// and the invariant held -- so it has to RETURN the report. Before there was a
// return value for it, the pattern this library is actually used through,
// `defer e.Destroy()`, reported success while the environment silently denied
// the wipe-enabling mprotect on every frozen enclave. The denial reaches every
// other enclave in the process, so losing it on the main path loses it
// everywhere.
func TestDestroyReportsTheDeniedMprotect(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("material for the public teardown path"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}

	denied := errors.New("mprotect denied by policy")
	prev := protectMemory
	t.Cleanup(func() { protectMemory = prev })
	protectMemory = func([]byte, protection) error { return denied }

	if derr := e.Destroy(); !errors.Is(derr, ErrReleasedWithoutWipe) {
		t.Fatalf("Destroy = %v, want ErrReleasedWithoutWipe", derr)
	}
	if e.IsAlive() {
		t.Error("the enclave reports itself alive after Destroy")
	}

	// Idempotent, and a second call has nothing left to report.
	if derr := e.Destroy(); derr != nil {
		t.Errorf("second Destroy = %v, want nil", derr)
	}
}

// TestDestroyIsNilOnAnOrdinaryTeardown is the control that makes the test
// above mean something: without it, an implementation that returned the sentinel
// unconditionally would pass.
func TestDestroyIsNilOnAnOrdinaryTeardown(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("material"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	if derr := e.Destroy(); derr != nil {
		t.Fatalf("Destroy on a clean teardown = %v, want nil", derr)
	}
}

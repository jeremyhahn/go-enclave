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

	"golang.org/x/sys/unix"
)

const (
	// subprocessMarker selects the child half of the fault-injection test below.
	subprocessMarker = "GO_ENCLAVE_LOCK_FAULT"

	// faultConfirmed is logged by the child once it has actually observed the
	// injected failure. The parent requires it, so that a child which skipped
	// (no permission to lower the limit) cannot be mistaken for a child which
	// verified the behavior.
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

	cmd := exec.Command(os.Args[0], "-test.run=^TestNewMemoryEnclave_LockedMemoryExhausted$", "-test.v")
	cmd.Env = append(os.Environ(), subprocessMarker+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("subprocess could not inject the fault:\n%s", out)
	}
	if !strings.Contains(string(out), faultConfirmed) {
		t.Fatalf("subprocess did not confirm the injected fault:\n%s", out)
	}
	if !strings.Contains(string(out), sourceWipeConfirmed) {
		t.Fatalf("subprocess did not confirm the source wipe:\n%s", out)
	}
	if !strings.Contains(string(out), copySourceIntactConfirmed) {
		t.Fatalf("subprocess did not confirm the copy constructor left its source intact:\n%s", out)
	}
}

func lockedMemoryExhaustionChild(t *testing.T) {
	t.Helper()

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Skipf("cannot read RLIMIT_MEMLOCK: %v", err)
	}

	// One page is below what a single guarded allocation needs, so the very
	// first lock attempt fails.
	limit := unix.Rlimit{Cur: uint64(os.Getpagesize()), Max: original.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		t.Skipf("cannot lower RLIMIT_MEMLOCK: %v", err)
	}

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

	cmd := exec.Command(os.Args[0], "-test.run=^TestMemoryEnclave_UnaffectedByForeignAllocationFailure$", "-test.v")
	cmd.Env = append(os.Environ(), foreignMarker+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("subprocess could not inject the fault:\n%s", out)
	}
	for _, want := range []string{foreignFailed, allocationRanDuringBorrow, enclaveSurvived} {
		if !strings.Contains(string(out), want) {
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
		t.Skipf("could not allocate the enclave under test: %v", err)
	}

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Skipf("cannot read RLIMIT_MEMLOCK: %v", err)
	}
	// Lowering the soft limit does not unlock pages already locked, so a stays
	// intact; only subsequent allocations fail.
	limit := unix.Rlimit{Cur: uint64(os.Getpagesize()), Max: original.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		t.Skipf("cannot lower RLIMIT_MEMLOCK: %v", err)
	}

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
			if string(b) != material {
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
		t.Skip("the foreign allocations unexpectedly succeeded; no fault was injected")
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
// path in Allocator.New (`a.used.Add(-n)`): a behavioral check on the enclave
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

	cmd := exec.Command(os.Args[0], "-test.run=^TestAllocator_ReleasesReservationOnLockFailure$", "-test.v")
	cmd.Env = append(os.Environ(), allocReleaseMarker+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("subprocess could not inject the fault:\n%s", out)
	}
	if !strings.Contains(string(out), allocReleaseConfirmed) {
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

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Skipf("cannot read RLIMIT_MEMLOCK: %v", err)
	}
	limit := unix.Rlimit{Cur: uint64(os.Getpagesize()), Max: original.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		t.Skipf("cannot lower RLIMIT_MEMLOCK: %v", err)
	}

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
	// (`a.used.Add(-n)`) is the only thing that returns it; delete that line
	// and this assertion fails.
	if got := a.InUse(); got != 0 {
		t.Fatalf("InUse = %d after releasing survivors, want 0 (failed allocation leaked its reservation)", got)
	}
	t.Log(allocReleaseConfirmed)
}

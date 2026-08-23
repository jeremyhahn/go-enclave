// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-enclave.
//
// go-enclave is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build linux

package enclave

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
}

const (
	// borrowMarker selects the child half of the purge-during-borrow test.
	borrowMarker = "GO_ENCLAVE_BORROW_PURGE"

	// borrowSurvived is logged by the child once it has read intact material
	// out of a borrow that was held across another goroutine's failed
	// allocation — the allocation whose failure purges and unmaps every live
	// buffer in the process.
	borrowSurvived = "borrow survived a process-wide purge triggered elsewhere"

	// purgeConfirmed is logged by the child once it has confirmed the purge
	// actually happened. Without it the test would pass vacuously on any run
	// where the foreign allocation happened to succeed.
	purgeConfirmed = "the foreign allocation failed and purged the process"
)

// TestMemoryEnclave_BorrowSurvivesForeignAllocationFailure covers the one
// lifetime hazard a per-enclave lock cannot reach.
//
// memguard's allocation failure path calls core.Purge before it panics, and
// Purge destroys EVERY live buffer in the process — memcall.Free, so the pages
// are unmapped, not merely wiped. It holds only memguard's own locks. So a
// goroutine parked inside WithBytes on enclave A, holding a slice into A's
// locked pages, can have those pages unmapped by an unrelated goroutine that
// exhausts locked memory constructing enclave B. Reading the slice afterwards
// faults the process; there is no error to return.
//
// The fix is package-wide: allocation takes purgeMu exclusively, every borrow
// takes it shared. This test parks a borrow, lets a foreign allocation fail
// underneath it, and then reads through the borrowed slice. It runs in a
// subprocess because the fault is injected process-wide and because the
// unfixed behavior is a SIGSEGV rather than a test failure.
func TestMemoryEnclave_BorrowSurvivesForeignAllocationFailure(t *testing.T) {
	if os.Getenv(borrowMarker) == "1" {
		borrowPurgeChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMemoryEnclave_BorrowSurvivesForeignAllocationFailure$", "-test.v")
	cmd.Env = append(os.Environ(), borrowMarker+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed (a fault here is the unfixed use-after-unmap): %v\n%s", err, out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("subprocess could not inject the fault:\n%s", out)
	}
	for _, want := range []string{purgeConfirmed, borrowSurvived} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
		}
	}
}

func borrowPurgeChild(t *testing.T) {
	t.Helper()

	const material = "server-private-key-material"

	// Allocate A while locked memory is still available.
	a, err := NewMemoryEnclave([]byte(material))
	if err != nil {
		t.Skipf("could not allocate the enclave under test: %v", err)
	}

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Skipf("cannot read RLIMIT_MEMLOCK: %v", err)
	}
	// Lowering the soft limit does not unlock pages already locked, so A stays
	// intact; only subsequent allocations fail.
	limit := unix.Rlimit{Cur: uint64(os.Getpagesize()), Max: original.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		t.Skipf("cannot lower RLIMIT_MEMLOCK: %v", err)
	}

	// order records which finished first. The borrow MUST complete before the
	// allocation does; if the allocation completes first it has already purged
	// and unmapped the pages the borrow is about to read.
	var order, borrowExit, allocExit atomic.Int32

	borrowed := make(chan struct{})
	release := make(chan struct{})
	borrowErr := make(chan error, 1)

	go func() {
		borrowErr <- a.WithBytes(func(b []byte) error {
			close(borrowed)
			<-release
			// Read AFTER the foreign allocation has had its chance to run. On
			// the unfixed code these pages are already unmapped and this
			// faults the process.
			if string(b) != material {
				return errors.New("borrowed material changed underneath the borrow")
			}
			// Record completion HERE, while the read lock is still held.
			// Recording it after WithBytes returns would race the woken
			// allocator, which by then may already have recorded its own
			// completion — a flake against correct code.
			borrowExit.Store(order.Add(1))
			return nil
		})
	}()

	<-borrowed

	attempting := make(chan struct{})
	allocErr := make(chan error, 1)
	go func() {
		// Announce entry BEFORE the call, so the release below cannot happen
		// until this goroutine is genuinely inside the allocation path. Without
		// this the test could pass vacuously by releasing the borrow before the
		// allocation was ever attempted.
		close(attempting)
		var e *MemoryEnclave
		var err error
		// Exhaust the one-page ceiling. Deliberately not destroyed.
		for i := 0; i < 64; i++ {
			e, err = NewMemoryEnclave([]byte(fmt.Sprintf("foreign-material-%d", i)))
			if err != nil {
				break
			}
			_ = e
		}
		allocExit.Store(order.Add(1))
		allocErr <- err
	}()

	<-attempting

	// Closing `attempting` only proves the goroutine was scheduled, not that it
	// reached the coordination point — it can be descheduled immediately after.
	// So observe the queued writer DIRECTLY. This test is in-package, so it can
	// interrogate purgeMu itself rather than infer from a timeout: TryRLock
	// fails exactly when a writer holds or is waiting for the lock, and the
	// borrow above already holds it shared, so a failed TryRLock can only mean
	// the allocator has reached purgeMu.Lock while this borrow is live.
	//
	// No probe goroutine and no timeout-as-evidence: a scheduler that never ran
	// the probe used to be indistinguishable from a genuinely blocked one.
	observed := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if !purgeMu.TryRLock() {
			observed = true
			break
		}
		purgeMu.RUnlock()
		time.Sleep(time.Millisecond)
	}
	if !observed {
		t.Fatal("no writer ever queued on purgeMu while the borrow was live; the allocator " +
			"either completed early (and purged) or never reached the lock — the test would be vacuous")
	}

	// It is parked on purgeMu, so it cannot have purged.
	if len(allocErr) != 0 {
		t.Fatal("the foreign allocation completed while a borrow was still in flight")
	}

	close(release)

	if err := <-borrowErr; err != nil {
		t.Fatalf("borrow: %v", err)
	}

	aErr := <-allocErr
	if aErr == nil {
		t.Skip("the foreign allocation unexpectedly succeeded; no purge was injected")
	}
	if !errors.Is(aErr, ErrLockedMemoryUnavailable) {
		t.Fatalf("foreign allocation err = %v, want ErrLockedMemoryUnavailable", aErr)
	}
	if borrowExit.Load() != 1 || allocExit.Load() != 2 {
		t.Fatalf("borrow finished at %d and the allocation at %d, want the borrow first",
			borrowExit.Load(), allocExit.Load())
	}
	// The purge really ran, so A is gone now — the documented cost of
	// locked-memory exhaustion, and proof this test was not vacuous.
	if a.IsAlive() {
		t.Fatal("expected the process-wide purge to have destroyed the enclave")
	}
	t.Log(purgeConfirmed)
	t.Log(borrowSurvived)
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

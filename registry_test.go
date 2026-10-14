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
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// errBorrowChanged reports material altered underneath a live borrow.
var errBorrowChanged = errors.New("borrowed material changed underneath the borrow")

// sweepHangBound is the deadline every test sweep runs under. It is a hang
// detector only: a sweep that waits forever returns a non-zero count the test
// names, instead of dying at the go test timeout.
const sweepHangBound = 60 * time.Second

// progressStallBound is how long a concurrency test's workers may go without
// finishing a single unit of work before the test calls them deadlocked. It
// bounds a stall, not the run: a slow or oversubscribed host under -race
// stretches the run, but it does not stop every worker for this long.
const progressStallBound = 60 * time.Second

// sweep runs WipeAll and fails the test on any error, so an unexpected canary
// failure is named rather than ignored.
func sweep(t *testing.T) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), sweepHangBound)
	defer cancel()
	remaining, err := WipeAll(ctx)
	if err != nil {
		t.Fatalf("WipeAll reported corruption where none was seeded: %v", err)
	}
	return remaining
}

// liveCount reports how many enclaves are on the shutdown ledger.
func liveCount() int {
	registryMu.Lock()
	defer registryMu.Unlock()
	return len(live)
}

// awaitProgress waits for done for as long as progress keeps moving. It
// returns false once progress has stood still for progressStallBound: every
// worker blocked at once, which a deadlock causes and a slow host does not.
func awaitProgress(done <-chan struct{}, progress *atomic.Int64) bool {
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	last, since := progress.Load(), time.Now()
	for {
		select {
		case <-done:
			return true
		case <-poll.C:
			if n := progress.Load(); n != last {
				last, since = n, time.Now()
			} else if time.Since(since) >= progressStallBound {
				return false
			}
		}
	}
}

// reclaimOnCleanup keeps a concurrency test's failure from leaving workers
// registering enclaves into the tests after it, which each need a clean
// ledger: at cleanup it halts the workers and the sweeper, waits for both while
// they make progress, and reclaims what they left.
func reclaimOnCleanup(t *testing.T, halt func(),
	workersDone <-chan struct{}, workerProgress *atomic.Int64,
	sweeperDone <-chan struct{}, sweeperProgress *atomic.Int64,
) {
	t.Helper()
	t.Cleanup(func() {
		halt()
		if !awaitProgress(workersDone, workerProgress) {
			t.Errorf("the workers were still blocked %v after being told to stop; their enclaves "+
				"stay in the ledger", progressStallBound)
			return
		}
		if !awaitProgress(sweeperDone, sweeperProgress) {
			t.Errorf("WipeAll was still running %v after being told to stop", progressStallBound)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), sweepHangBound)
		defer cancel()
		_, _ = WipeAll(ctx)
	})
}

// TestWipeAll_DestroysEveryLiveEnclave pins that nothing this package allocated
// survives a sweep. It counts the ledger rather than trusting the return value.
func TestWipeAll_DestroysEveryLiveEnclave(t *testing.T) {
	const n = 8
	material := bytes.Repeat([]byte{0xC7}, 48)

	before := liveCount()

	held := make([]*Memory, 0, n)
	for i := 0; i < n; i++ {
		e, err := newMemory(append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("NewMemory: %v", err)
		}
		held = append(held, e)
	}
	if got := liveCount(); got != before+n {
		t.Fatalf("ledger holds %d, want %d: construction did not register", got, before+n)
	}

	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll left %d enclaves, want 0", remaining)
	}

	for i, e := range held {
		if e.IsAlive() {
			t.Errorf("enclave %d is still alive after WipeAll", i)
		}
		if e.Size() != 0 {
			t.Errorf("enclave %d reports size %d after WipeAll", i, e.Size())
		}
		if holds(e, material) {
			t.Errorf("enclave %d still holds its material after WipeAll", i)
		}
	}
	if got := liveCount(); got != 0 {
		t.Errorf("ledger holds %d after WipeAll, want 0", got)
	}
}

// TestWipeAll_IsIdempotentAndEmptySafe covers the two calls a shutdown path
// makes by accident: one when nothing was ever allocated, and a second after
// the first already swept.
func TestWipeAll_IsIdempotentAndEmptySafe(t *testing.T) {
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll on an empty ledger = %d, want 0", remaining)
	}

	e, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("first WipeAll = %d, want 0", remaining)
	}
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("second WipeAll = %d, want 0", remaining)
	}
	if e.IsAlive() {
		t.Error("the enclave survived WipeAll")
	}

	// And the enclave's own Destroy afterwards is still a no-op, not a panic or
	// a double release.
	e.Destroy()
	e.Destroy()
}

// TestWipeAll_AlreadyDestroyedIsANoOp pins that Destroy takes its enclave off
// the ledger, so the registry does not retain every enclave ever created.
func TestWipeAll_AlreadyDestroyedIsANoOp(t *testing.T) {
	before := liveCount()

	e, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	if got := liveCount(); got != before+1 {
		t.Fatalf("ledger holds %d after construction, want %d", got, before+1)
	}

	e.Destroy()
	if got := liveCount(); got != before {
		t.Errorf("ledger holds %d after Destroy, want %d: Destroy did not deregister", got, before)
	}

	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll = %d, want 0", remaining)
	}
}

// TestWipeAll_ABorrowThatOutlastsCtxIsCountedNotUnmapped pins that a borrow
// outlasting ctx is skipped and counted, never unmapped, while the un-borrowed
// enclave is still reclaimed. ctx is canceled through sweepWaitingForTest, so
// the wait's ctx branch is exercised without a clock.
func TestWipeAll_ABorrowThatOutlastsCtxIsCountedNotUnmapped(t *testing.T) {
	material := bytes.Repeat([]byte{0x3C}, 40)

	borrowed, err := newMemory(append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	other, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}

	inBorrow := make(chan struct{})
	release := make(chan struct{})
	borrowDone := make(chan error, 1)
	go func() {
		borrowDone <- borrowed.WithBytes(func(b []byte) error {
			close(inBorrow)
			<-release
			// Read AFTER the sweep has returned. If WipeAll had unmapped these
			// pages this faults the process rather than failing the test.
			if !bytes.Equal(b, material) {
				return errBorrowChanged
			}
			return nil
		})
	}()
	<-inBorrow

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits atomic.Int32
	swapSeam(t, &sweepWaitingForTest, func() {
		waits.Add(1)
		cancel()
	})

	swept := make(chan int, 1)
	go func() { n, _ := WipeAll(ctx); swept <- n }()

	var remaining int
	select {
	case remaining = <-swept:
	case <-time.After(sweepHangBound):
		// A failure, not a skip: with the borrow still parked the sweep must
		// return once ctx ends.
		t.Fatal("WipeAll did not return after its context was canceled with a borrow in flight: " +
			"the wait is not bounded by ctx; a stalled holder would hang shutdown")
	}

	if got := waits.Load(); got != 1 {
		t.Errorf("the sweep waited %d times, want exactly 1: it found the borrow held once, waited, "+
			"and its context ended", got)
	}
	if remaining != 1 {
		t.Errorf("WipeAll = %d, want 1: the borrowed enclave should be skipped and counted", remaining)
	}
	if other.IsAlive() {
		t.Error("the un-borrowed enclave was not wiped; one live borrow stopped the whole sweep")
	}

	close(release)
	if err := <-borrowDone; err != nil {
		t.Fatalf("borrow: %v", err)
	}
	if !borrowed.IsAlive() {
		t.Error("the borrowed enclave was destroyed although the borrow outlasted the sweep's context")
	}

	// Once the borrow is done the enclave is still on the ledger, so a second
	// sweep reclaims it — the retry the count is telling the caller to make.
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("second WipeAll = %d, want 0 once the borrow has returned", remaining)
	}
	if borrowed.IsAlive() {
		t.Error("the previously borrowed enclave survived the second sweep")
	}
}

// TestWipeAll_ReturnsTheAllocatorReservations pins that the sweep settles the
// Allocator budget on the same terms Destroy does.
func TestWipeAll_ReturnsTheAllocatorReservations(t *testing.T) {
	a, err := newBudgetAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	for i := 0; i < 4; i++ {
		if _, err := a.NewSized(64); err != nil {
			t.Fatalf("NewSized: %v", err)
		}
	}
	if a.InUse() == 0 {
		t.Fatal("nothing was reserved; the test would be vacuous")
	}

	if remaining := sweep(t); remaining != 0 {
		t.Fatalf("WipeAll = %d, want 0", remaining)
	}
	if got := a.InUse(); got != 0 {
		t.Errorf("InUse = %d after WipeAll, want 0: the sweep did not return the reservations", got)
	}
	if got := a.Available(); got != 8*pageSize {
		t.Errorf("Available = %d after WipeAll, want the full budget", got)
	}
}

// TestWipeAll_ConcurrentWithConstructionAndDestruction runs the sweep against
// live New and Destroy traffic for the race detector, and pins that it does not
// deadlock against Destroy, which takes the same ledger lock. Whether a zero is
// truthful is covered by TestWipeAll_DoesNotReturnZeroWhileAnEnclaveIsAlive.
//
// The sweeper is not in the worker WaitGroup: it stops when the workers finish,
// so waiting on a group containing it would deadlock.
func TestWipeAll_ConcurrentWithConstructionAndDestruction(t *testing.T) {
	const goroutines, iterations = 50, 100

	// completed and sweeps are the progress the watchdog reads. halt ends the
	// workers and the sweeper, early when the test fails.
	var completed, sweeps atomic.Int64
	quit := make(chan struct{})
	stop := make(chan struct{})
	var halting sync.Once
	halt := func() { halting.Do(func() { close(quit); close(stop) }) }

	var workers sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < iterations; i++ {
				select {
				case <-quit:
					return
				default:
				}
				e, err := newMemorySized(64)
				if err != nil {
					t.Errorf("NewMemorySized: %v", err)
					return
				}
				// A sweep may already have destroyed it; either outcome is
				// correct, and Destroy is a no-op on one the sweep took.
				_ = e.WithBytes(func([]byte) error { return nil })
				e.Destroy()
				completed.Add(1)
			}
		}()
	}

	sweeperDone := make(chan struct{})
	go func() {
		defer close(sweeperDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_, _ = WipeAll(context.Background())
			sweeps.Add(1)
		}
	}()

	workersDone := make(chan struct{})
	go func() {
		workers.Wait()
		close(workersDone)
	}()

	reclaimOnCleanup(t, halt, workersDone, &completed, sweeperDone, &sweeps)

	if !awaitProgress(workersDone, &completed) {
		t.Fatalf("construction and destruction made no progress for %v alongside a running WipeAll "+
			"(%d of %d iterations done): they are deadlocked against the registry lock",
			progressStallBound, completed.Load(), goroutines*iterations)
	}

	halt()
	if !awaitProgress(sweeperDone, &sweeps) {
		t.Fatalf("WipeAll did not return within %v after the workers finished", progressStallBound)
	}

	if remaining := sweep(t); remaining != 0 {
		t.Errorf("final WipeAll = %d, want 0", remaining)
	}
	if got := liveCount(); got != 0 {
		t.Errorf("ledger holds %d after everything drained, want 0", got)
	}
}

// TestWipeAll_DoesNotReturnZeroWhileAnEnclaveIsAlive pins that an enclave
// registered after the sweep's snapshot is either reclaimed or counted, never
// reported as zero. The late registration runs from an Allocator release
// closure, which WipeAll invokes inside the sweep after the snapshot.
func TestWipeAll_DoesNotReturnZeroWhileAnEnclaveIsAlive(t *testing.T) {
	requireCleanLedger(t)

	trigger, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}

	var (
		lateMu sync.Mutex
		late   *Memory
	)
	// Runs inside WipeAll, after the snapshot that will never contain `late`.
	trigger.release = func() {
		e, cerr := newMemorySized(32)
		lateMu.Lock()
		late = e
		lateMu.Unlock()
		if cerr != nil {
			t.Errorf("constructing during the sweep: %v", cerr)
		}
	}

	remaining := sweep(t)

	lateMu.Lock()
	got := late
	lateMu.Unlock()
	if got == nil {
		t.Fatal("the release hook never ran; the test did not exercise the race it exists for")
	}

	// Either the same call wiped it, or the count says it is still there. What
	// must never happen is zero while it is alive.
	if remaining == 0 && got.IsAlive() {
		t.Error("WipeAll returned 0 while an enclave registered during the sweep was still alive, " +
			"mapped and holding locked memory: the documented guarantee that zero means everything " +
			"was wiped is false")
	}
	if got.IsAlive() {
		t.Errorf("the late enclave survived the sweep (WipeAll = %d); reclaiming the trigger earns a "+
			"re-read that should have reached it", remaining)
	}
	if n := liveCount(); n != remaining {
		t.Errorf("WipeAll returned %d but the ledger holds %d: the count is not the ledger", remaining, n)
	}

	got.Destroy()
	trigger.Destroy()
}

// TestWipeAll_ConcurrentWithAllocatorConstructionKeepsTheBudgetExact pins
// publication order: an enclave must not reach the ledger before its release
// callback is installed, or a sweep races the assignment and destroys it with
// the charge never returned. The race detector is the oracle for the race (CI
// runs -race); the budget assertion checks every reservation is settled once.
//
// No sleeps. A KICK before every construction runs one sweep concurrently with
// it; on every other iteration a SETTLE waits for a sweep that started after
// New returned, so the sweep-destroys-it path is exercised deterministically.
//
// Needs only a few locked pages at once (64 KiB RLIMIT_MEMLOCK is enough); a
// refused lock is a failure, not a skip.
func TestWipeAll_ConcurrentWithAllocatorConstructionKeepsTheBudgetExact(t *testing.T) {
	requireCleanLedger(t)

	const (
		goroutines = 4
		iterations = 26
		payload    = 4 << 10
		budget     = 8 << 20
	)

	a, err := newBudgetAllocator(budget)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var swept, settled, verified atomic.Int64
	material := bytes.Repeat([]byte{0x5A}, payload)

	// Phase 1, QUIESCENT: a successful return is a usable enclave holding
	// exactly its material. Checked with no sweeper running, because it is a
	// property of construction rather than of the race.
	func() {
		e, err := a.admitData(append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Allocator.New with no sweep running: %v (a refused lock means the runner's "+
				"RLIMIT_MEMLOCK is below one page — a provisioning defect, not a skip)", err)
		}
		defer e.Destroy()
		if !e.IsAlive() {
			t.Fatal("Allocator.New returned a destroyed enclave with no sweep running")
		}
		if !holds(e, material) {
			t.Fatal("Allocator.New returned an enclave that does not hold its material")
		}
	}()

	// The sweeper runs WipeAll only when asked, and never between requests.
	// begun and sweeps are the progress the stall check reads. halt ends the
	// workers and the sweeper, early when the test fails.
	var begun, sweeps atomic.Int64
	kick := make(chan struct{}, 1)
	settle := make(chan chan struct{})
	stop := make(chan struct{})
	var halting sync.Once
	halt := func() { halting.Do(func() { close(stop) }) }
	sweeperDone := make(chan struct{})
	go func() {
		defer close(sweeperDone)
		for {
			select {
			case <-stop:
				return
			case <-kick:
				_, _ = WipeAll(context.Background())
				sweeps.Add(1)
			case reply := <-settle:
				_, _ = WipeAll(context.Background())
				sweeps.Add(1)
				close(reply)
			}
		}
	}()

	var workers sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < iterations; i++ {
				// A worker begins an iteration only once the one before has
				// finished, so begun moves exactly when the workers do.
				select {
				case <-stop:
					return
				default:
				}
				begun.Add(1)

				// A sweep in flight while New publishes. Non-blocking: one
				// pending kick already guarantees the next sweep.
				select {
				case kick <- struct{}{}:
				default:
				}

				e, err := a.admitData(append([]byte(nil), material...))
				if err != nil {
					t.Errorf("Allocator.New: %v (ErrLockedMemoryUnavailable here means the runner's "+
						"RLIMIT_MEMLOCK cannot hold %d one-page enclaves at once — provision it)", err, goroutines)
					return
				}

				if i%2 == 0 {
					// A sweep that starts after New returned certainly destroys the
					// enclave: the path on which a missing refund is permanent.
					reply := make(chan struct{})
					select {
					case settle <- reply:
					case <-stop:
						return
					}
					<-reply
					if e.IsAlive() {
						t.Errorf("an enclave published before a WipeAll began survived that sweep")
						e.Destroy()
						continue
					}
					settled.Add(1)
					swept.Add(1)
					continue
				}

				// Racing a kicked sweep for this enclave: whoever gets it
				// first destroys it, and the refund must happen exactly once
				// either way.
				if e.IsAlive() {
					if holds(e, material) {
						verified.Add(1)
					}
					e.Destroy()
					continue
				}
				swept.Add(1)
			}
		}()
	}

	workersDone := make(chan struct{})
	go func() {
		workers.Wait()
		close(workersDone)
	}()

	reclaimOnCleanup(t, halt, workersDone, &begun, sweeperDone, &sweeps)

	if !awaitProgress(workersDone, &begun) {
		t.Fatalf("allocator-backed construction made no progress for %v alongside a running WipeAll "+
			"(%d of %d iterations begun): it is blocked against the sweep, not merely slow",
			progressStallBound, begun.Load(), goroutines*iterations)
	}

	halt()
	if !awaitProgress(sweeperDone, &sweeps) {
		t.Fatalf("WipeAll did not return within %v after the workers finished", progressStallBound)
	}

	if remaining := sweep(t); remaining != 0 {
		t.Errorf("final WipeAll = %d, want 0", remaining)
	}
	t.Logf("%d of %d enclaves were destroyed by a sweep rather than by their caller (%d of them by a "+
		"sweep the worker waited for); %d came back alive and holding exactly their material",
		swept.Load(), goroutines*iterations, settled.Load(), verified.Load())

	if want := int64(goroutines * iterations / 2); settled.Load() != want && !t.Failed() {
		t.Errorf("%d enclaves were reclaimed by a settled sweep, want %d: the branch where a lost "+
			"refund would be permanent was not exercised as designed", settled.Load(), want)
	}

	if got := a.InUse(); got != 0 {
		t.Errorf("InUse = %d after everything drained, want 0: a reservation was lost, which happens "+
			"when the sweep destroys an enclave whose release callback is not installed yet", got)
	}
	if got := a.Available(); got != budget {
		t.Errorf("Available = %d after everything drained, want the full budget %d", got, budget)
	}
}

// TestWipeAll_RetriesAReaderRatherThanAbandoningIt pins that every pass
// reconsiders every registered enclave, so one whose write TryLock lost to a
// momentary reader is retried rather than abandoned. The reader is released
// from inside the sweep and the sweep waits for the read lock to drop.
//
// Paired with TestWipeAll_ABorrowEndingWakesTheSweep; neither implies the
// other. Repeated 16 times because ledger order is random and the defect needs
// the held enclave reached before the gate.
func TestWipeAll_RetriesAReaderRatherThanAbandoningIt(t *testing.T) {
	requireCleanLedger(t)

	const trials = 16

	for trial := 0; trial < trials; trial++ {
		a, err := newBudgetAllocator(16 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}

		// held is the enclave a reader is touching when the sweep arrives.
		held, err := newMemorySized(64)
		if err != nil {
			t.Fatalf("trial %d: NewMemorySized: %v", trial, err)
		}
		// gate runs code INSIDE the sweep, after the batch has been taken.
		gate, err := a.admitSized(64)
		if err != nil {
			held.Destroy()
			t.Fatalf("trial %d: Allocator.NewSized: %v", trial, err)
		}

		inBorrow := make(chan struct{})
		release := make(chan struct{})
		readerDone := make(chan struct{})
		go func() {
			defer close(readerDone)
			// A read lock, exactly as IsAlive or Size would take. Held only
			// until the sweep says go — a momentary reader, not a stuck one.
			_ = held.WithBytes(func([]byte) error {
				close(inBorrow)
				<-release
				return nil
			})
		}()
		<-inBorrow

		refund := gate.release
		gate.release = func() {
			refund()
			// Let the reader go, then WAIT for the read lock to be dropped
			// before the sweep continues. Synchronous by construction.
			close(release)
			<-readerDone
		}

		// Bounded: a tryRelease that blocked on the lock would deadlock here,
		// since the reader is released only from inside WipeAll.
		swept := make(chan int, 1)
		go func() { n, _ := WipeAll(context.Background()); swept <- n }()

		var remaining int
		select {
		case remaining = <-swept:
		case <-time.After(30 * time.Second):
			t.Fatalf("trial %d: WipeAll did not return within 30s while an enclave was being read. "+
				"It is WAITING for the read lock rather than trying for it, which deadlocks against a "+
				"reader that this sweep is itself responsible for releasing", trial)
		}

		if remaining != 0 {
			t.Fatalf("trial %d: WipeAll = %d, want 0. An enclave whose reader had already finished was "+
				"left mapped and locked: a lost TryLock was treated as permanent rather than as "+
				"'not right now'", trial, remaining)
		}
		if held.IsAlive() {
			t.Fatalf("trial %d: the enclave read during the sweep survived it, still holding locked "+
				"memory, after its reader finished", trial)
		}
		if n := liveCount(); n != 0 {
			t.Fatalf("trial %d: ledger holds %d after the sweep, want 0", trial, n)
		}
		if got := a.InUse(); got != 0 {
			t.Fatalf("trial %d: InUse = %d after the sweep, want 0", trial, got)
		}
	}
}

// TestWipeAll_DoesNotPanicOnACorruptCanaryAndFinishesTheSweep pins that a
// failed canary neither panics nor stops the sweep: all five enclaves are
// checked, since ledger order is random, and the corrupt one still returns its
// reservation because its region was wiped and unmapped.
func TestWipeAll_DoesNotPanicOnACorruptCanaryAndFinishesTheSweep(t *testing.T) {
	requireCleanLedger(t)

	const count, corruptAt = 5, 2

	a, err := newBudgetAllocator(16 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	held := make([]*Memory, 0, count)
	for i := 0; i < count; i++ {
		// Sized, so the pages stay writable; a frozen enclave would fault on the
		// canary write below.
		e, err := a.admitSized(64)
		if err != nil {
			t.Fatalf("NewSized: %v", err)
		}
		if err := e.WithBytes(func(b []byte) error {
			copy(b, bytes.Repeat([]byte{byte(0xB0 + i)}, len(b)))
			return nil
		}); err != nil {
			t.Fatalf("fill: %v", err)
		}
		held = append(held, e)
	}

	if len(held[corruptAt].m.canary) == 0 {
		t.Fatal("no canary slack at this size; the corruption would not be detectable and the test would be vacuous")
	}
	// Exactly what a buffer underflow through a retained slice would do.
	held[corruptAt].m.canary[0] ^= 0xFF

	reserved := a.InUse()
	if reserved == 0 {
		t.Fatal("nothing was reserved; the budget half of the test would be vacuous")
	}

	var (
		remaining int
		sweepErr  error
		panicked  any
	)
	func() {
		defer func() { panicked = recover() }()
		remaining, sweepErr = WipeAll(context.Background())
	}()

	if panicked != nil {
		t.Fatalf("WipeAll PANICKED on a corrupt canary (%v). Its documentation promises it never does, "+
			"because a sweep that aborts partway leaves every enclave it had not reached still holding "+
			"material at exit", panicked)
	}

	for i, e := range held {
		if e.IsAlive() {
			t.Errorf("enclave %d survived the sweep; with the corrupt one at index %d this is the "+
				"sweep aborting at the failure instead of counting it and going on", i, corruptAt)
		}
	}
	// The corruption must be reported, not just survived.
	if sweepErr == nil {
		t.Error("WipeAll returned a nil error after detecting a corrupt canary: the memory was reclaimed " +
			"but the corruption was never reported, so a shutdown caller cannot tell a clean wipe from " +
			"detected memory corruption")
	}
	if sweepErr != nil && !errors.Is(sweepErr, ErrEnclaveCorrupted) {
		t.Errorf("WipeAll error = %v, want one matching ErrEnclaveCorrupted: callers match the sentinel, "+
			"exactly as they do on Destroy's error", sweepErr)
	}

	// The corrupt enclave's pages went back, so it is not in the count.
	if remaining != 0 {
		t.Errorf("WipeAll = %d, want 0: a detected corruption still counts as released — the region was "+
			"wiped and unmapped", remaining)
	}
	if n := liveCount(); n != 0 {
		t.Errorf("ledger holds %d after the sweep, want 0", n)
	}
	if got := a.InUse(); got != 0 {
		t.Errorf("InUse = %d after the sweep, want 0: the corrupt enclave's reservation was not returned, "+
			"though its pages went back to the kernel", got)
	}

	// A second sweep reports nothing: the error describes what THIS call
	// detected, not a standing condition of the process.
	if remaining, err := WipeAll(context.Background()); remaining != 0 || err != nil {
		t.Errorf("second WipeAll = (%d, %v), want (0, nil): the corrupt enclaves are gone, so the "+
			"corruption report must not persist across calls", remaining, err)
	}
}

// TestWipeAll_ReportsHowManyEnclavesWereCorrupt pins that one error carries
// the number of corrupt enclaves rather than one joined sentinel per enclave.
func TestWipeAll_ReportsHowManyEnclavesWereCorrupt(t *testing.T) {
	requireCleanLedger(t)

	const total, corruptCount = 5, 3

	for i := 0; i < total; i++ {
		e, err := newMemorySized(64)
		if err != nil {
			t.Fatalf("NewMemorySized: %v", err)
		}
		if i < corruptCount {
			if len(e.m.canary) == 0 {
				t.Fatal("no canary slack at this size; the test would be vacuous")
			}
			e.m.canary[0] ^= 0xFF
		}
	}

	remaining, err := WipeAll(context.Background())
	if remaining != 0 {
		t.Errorf("WipeAll = %d, want 0", remaining)
	}
	if !errors.Is(err, ErrEnclaveCorrupted) {
		t.Fatalf("WipeAll error = %v, want one matching ErrEnclaveCorrupted", err)
	}
	if got := err.Error(); !strings.Contains(got, strconv.Itoa(corruptCount)) {
		t.Errorf("WipeAll error = %q, want it to name how many enclaves were corrupt (%d): an operator "+
			"reading one line needs the number, and a single sentinel cannot carry it", got, corruptCount)
	}
}

// TestWipeAll_ReportsCorruptionWhoseReleaseWasRefused pins that a corrupt
// enclave whose munmap is refused is both counted and reported, and reported
// once although attempted twice. A companion enclave that releases normally
// earns the second pass, whose retry must skip the already-done unlock.
func TestWipeAll_ReportsCorruptionWhoseReleaseWasRefused(t *testing.T) {
	requireCleanLedger(t)

	e, err := newMemorySized(64)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	if len(e.m.canary) == 0 {
		t.Fatal("no canary slack at this size; the test would be vacuous")
	}
	e.m.canary[0] ^= 0xFF
	companion, err := newMemorySized(64)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}

	// Registered first, the sweep runs after the seams are restored.
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })
	installStrictUnlock(t)
	refused := &e.m.memory[0]
	var refusals atomic.Int32
	prev := unmapMemory
	swapSeam(t, &unmapMemory, func(b []byte) error {
		if &b[0] == refused {
			refusals.Add(1)
			return errors.New("munmap: cannot allocate memory")
		}
		return prev(b)
	})

	remaining, err := WipeAll(context.Background())
	if remaining != 1 {
		t.Errorf("WipeAll = %d with the corrupt enclave's munmap refused, want 1: its pages are still mapped", remaining)
	}
	if !errors.Is(err, ErrEnclaveCorrupted) {
		t.Fatalf("WipeAll error = %v, want one matching ErrEnclaveCorrupted: the corruption was detected "+
			"and then lost because the pages could not be released", err)
	}
	if got := err.Error(); !strings.Contains(got, "1 of the swept enclaves failed canary verification") {
		t.Errorf("WipeAll error = %q, want it to count the one corrupt enclave once, not once per pass", got)
	}
	if got := refusals.Load(); got != 2 {
		t.Errorf("the corrupt enclave's munmap was attempted %d times in one sweep, want 2: reclaiming the "+
			"companion must earn the retry, or the once-not-per-attempt assertion above is vacuous", got)
	}
	if companion.IsAlive() {
		t.Error("the companion enclave survived the sweep")
	}

	unmapMemory = prev
	remaining, err = WipeAll(context.Background())
	if remaining != 0 {
		t.Errorf("WipeAll = %d once munmap is allowed again, want 0", remaining)
	}
	if !errors.Is(err, ErrEnclaveCorrupted) {
		t.Errorf("the sweep that reclaimed the corrupt enclave reported %v, want ErrEnclaveCorrupted", err)
	}
}

// TestWipeAll_ReportsNoErrorWhenNothingIsCorrupt is the control for the
// corruption tests: a clean sweep reports nil.
func TestWipeAll_ReportsNoErrorWhenNothingIsCorrupt(t *testing.T) {
	requireCleanLedger(t)

	for i := 0; i < 4; i++ {
		if _, err := newMemorySized(64); err != nil {
			t.Fatalf("NewMemorySized: %v", err)
		}
	}

	remaining, err := WipeAll(context.Background())
	if remaining != 0 {
		t.Errorf("WipeAll = %d, want 0", remaining)
	}
	if err != nil {
		t.Errorf("WipeAll error = %v, want nil: nothing was corrupt, and an error here would make the "+
			"corruption signal meaningless", err)
	}
}

// TestWipeAll_AFailedReleaseKeepsBothTheChargeAndTheLedgerEntry pins that an
// enclave whose release the kernel refuses keeps its Allocator charge (the
// pages are still locked) and stays on the ledger to be counted and retried.
// The mprotect and unmap are refused through their seams.
func TestWipeAll_AFailedReleaseKeepsBothTheChargeAndTheLedgerEntry(t *testing.T) {
	if remaining, err := WipeAll(context.Background()); remaining != 0 || err != nil {
		t.Fatalf("this test needs a clean ledger; WipeAll = %d, %v", remaining, err)
	}

	a, err := newBudgetAllocator(16 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.admitSized(64)
	if err != nil {
		t.Fatalf("could not allocate: %v", err)
	}
	reserved := a.InUse()
	if reserved == 0 {
		t.Fatal("nothing was reserved; the test would be vacuous")
	}

	lift := denyProtectAndUnmap(t)

	remaining, serr := WipeAll(context.Background())

	if serr != nil {
		t.Errorf("WipeAll err = %v, want nil: a refused unmap is not corruption", serr)
	}
	if remaining != 1 {
		t.Errorf("WipeAll = %d, want 1: an enclave whose pages are still mapped must be counted", remaining)
	}
	if n := liveCount(); n != 1 {
		t.Errorf("ledger holds %d, want 1: an enclave that could not be released must stay on the "+
			"ledger so a later sweep retries it — dropping it reports success while the material "+
			"is still mapped and locked", n)
	}
	if got := a.InUse(); got != reserved {
		t.Errorf("InUse = %d after a FAILED release, want the unchanged %d: the charge was returned "+
			"while the kernel still holds the pages, so the allocator will over-admit", got, reserved)
	}
	// Not alive: NewSized is mutable, so the early wipe destroyed the material
	// before the refused unmap. The retry still works through the mapping.
	if e.IsAlive() {
		t.Error("the enclave reports itself alive although its material was " +
			"already wiped by the early wipe")
	}

	// With the refusals lifted, the retry the count was asking for settles both.
	lift()
	remaining, serr = WipeAll(context.Background())
	if serr != nil && !errors.Is(serr, ErrEnclaveCorrupted) {
		t.Errorf("retry WipeAll err = %v", serr)
	}
	if remaining != 0 {
		t.Errorf("retry WipeAll = %d, want 0", remaining)
	}
	if got := a.InUse(); got != 0 {
		t.Errorf("InUse = %d after the successful retry, want 0", got)
	}
}

// TestWipeAll_ABorrowEndingWakesTheSweep pins that the end of a borrow wakes a
// sweep waiting for it and that call reclaims the enclave. ctx is Background,
// so only the wake-up can end the wait, and the borrow ends only once the sweep
// is waiting (sweepWaitingForTest).
//
// Paired with TestWipeAll_RetriesAReaderRatherThanAbandoningIt: this one pins
// the wait, that one pins that every pass reconsiders every entry.
func TestWipeAll_ABorrowEndingWakesTheSweep(t *testing.T) {
	if remaining := sweep(t); remaining != 0 {
		t.Fatalf("this test needs a clean ledger; WipeAll = %d", remaining)
	}

	e, err := newMemorySized(64)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}

	inBorrow := make(chan struct{})
	release := make(chan struct{})
	borrowDone := make(chan struct{})
	go func() {
		defer close(borrowDone)
		_ = e.WithBytes(func([]byte) error {
			close(inBorrow)
			<-release
			return nil
		})
	}()
	<-inBorrow

	var waits atomic.Int32
	swapSeam(t, &sweepWaitingForTest, func() {
		if waits.Add(1) == 1 {
			// End the borrow inside the wait window: its wake-up is the only
			// thing that can end a Background wait.
			close(release)
			<-borrowDone
		}
	})

	type result struct {
		n   int
		err error
	}
	swept := make(chan result, 1)
	go func() {
		n, err := WipeAll(context.Background())
		swept <- result{n, err}
	}()

	var r result
	select {
	case r = <-swept:
	case <-time.After(sweepHangBound):
		t.Fatal("WipeAll(context.Background()) did not return after the borrow it was waiting for ended: " +
			"the borrow's release did not wake it — a lost wake-up, which under a context with no " +
			"deadline is a shutdown that never finishes")
	}

	if r.err != nil {
		t.Errorf("WipeAll err = %v, want nil", r.err)
	}
	if r.n != 0 {
		t.Errorf("WipeAll = %d, want 0: the borrow ended while the sweep was waiting, so the same call "+
			"must have reclaimed it", r.n)
	}
	if e.IsAlive() {
		t.Error("the enclave survived a sweep that was woken by the end of its borrow")
	}
	if got := waits.Load(); got != 1 {
		t.Errorf("the sweep waited %d times, want exactly 1: one borrow, one end, one wake-up", got)
	}
}

// The tests below pin the event-driven wait, the ctx bound, termination
// against endless construction, SweepError, and the holder handshake. None
// sleeps; every ordering is made by a channel or a seam inside the sweep.

// holdBorrow starts a WithBytes borrow on e in its own goroutine and returns
// once it is inside the borrow. end finishes the borrow and waits for it to
// return; it is idempotent and also registered as cleanup, so a failing test
// never leaves the borrow parked.
func holdBorrow(t *testing.T, e *Memory) (end func()) {
	t.Helper()
	inBorrow := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = e.WithBytes(func([]byte) error {
			close(inBorrow)
			<-release
			return nil
		})
	}()
	<-inBorrow
	var once sync.Once
	end = func() {
		once.Do(func() {
			close(release)
			<-done
		})
	}
	t.Cleanup(end)
	return end
}

// sweepResult is one WipeAll's return, carried over a channel.
type sweepResult struct {
	n   int
	err error
}

// sweepAsync runs WipeAll(ctx) in its own goroutine and returns its result, or
// fails the test at sweepHangBound with what a hang there means.
func sweepAsync(t *testing.T, ctx context.Context, hang string) sweepResult {
	t.Helper()
	out := make(chan sweepResult, 1)
	go func() {
		n, err := WipeAll(ctx)
		out <- sweepResult{n, err}
	}()
	select {
	case r := <-out:
		return r
	case <-time.After(sweepHangBound):
		t.Fatalf("WipeAll did not return within %v: %s", sweepHangBound, hang)
		return sweepResult{}
	}
}

// TestWipeAll_ACanceledCtxStillSweepsWhatIsFree pins that a done ctx means "do
// not wait", not a refusal: everything free is reclaimed, the held enclave is
// counted, and the sweep never enters its wait.
func TestWipeAll_ACanceledCtxStillSweepsWhatIsFree(t *testing.T) {
	requireCleanLedger(t)

	free, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	held, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	end := holdBorrow(t, held)

	var waits atomic.Int32
	swapSeam(t, &sweepWaitingForTest, func() { waits.Add(1) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := sweepAsync(t, ctx, "a canceled context must never be waited on")

	if r.err != nil {
		t.Errorf("WipeAll err = %v, want nil: a context ending is not something the sweep found", r.err)
	}
	if r.n != 1 {
		t.Errorf("WipeAll = %d, want 1: the held enclave is still held", r.n)
	}
	if free.IsAlive() {
		t.Error("the free enclave survived a sweep under a canceled context; an expired deadline must " +
			"still reclaim everything that needs no waiting")
	}
	if !held.IsAlive() {
		t.Error("the held enclave was destroyed underneath its borrow")
	}

	if got := waits.Load(); got != 0 {
		t.Errorf("the sweep blocked in its wait %d times under a canceled context, want 0", got)
	}

	end()
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll after the borrow ended = %d, want 0", remaining)
	}
}

// TestWipeAll_ANilCtxNeverWaitsAndNeverPanics pins that a nil ctx is treated
// as an already-done one: no panic, no wait.
func TestWipeAll_ANilCtxNeverWaitsAndNeverPanics(t *testing.T) {
	requireCleanLedger(t)

	free, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	held, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	end := holdBorrow(t, held)

	var waits atomic.Int32
	swapSeam(t, &sweepWaitingForTest, func() { waits.Add(1) })

	var nilCtx context.Context // a variable, so vet's nil-context check is not what is being tested
	var r sweepResult
	if p := panicValue(func() { r = sweepAsync(t, nilCtx, "a nil context must never be waited on") }); p != nil {
		t.Fatalf("WipeAll(nil) panicked with %v; it is documented never to panic", p)
	}
	if r.n != 1 || r.err != nil {
		t.Errorf("WipeAll(nil) = (%d, %v), want (1, nil): the held enclave counted, nothing waited for", r.n, r.err)
	}
	if free.IsAlive() {
		t.Error("the free enclave survived WipeAll(nil)")
	}
	if got := waits.Load(); got != 0 {
		t.Errorf("WipeAll(nil) blocked in its wait %d times, want 0", got)
	}

	end()
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll after the borrow ended = %d, want 0", remaining)
	}
}

// TestWipeAll_AConstructorThatNeverStopsCannotKeepTheSweepRunning pins
// termination under Background: each enclave constructs its successor from
// its own release, inside the sweep, yet only entries owed at the first pass
// earn another pass. The late link left behind is counted.
func TestWipeAll_AConstructorThatNeverStopsCannotKeepTheSweepRunning(t *testing.T) {
	requireCleanLedger(t)

	var (
		stop  atomic.Bool
		made  atomic.Int32
		cerrs = make(chan error, 1)
	)
	var link func() *Memory
	link = func() *Memory {
		e, err := newMemorySized(32)
		if err != nil {
			select {
			case cerrs <- err:
			default:
			}
			return nil
		}
		e.release = func() {
			if !stop.Load() {
				made.Add(1)
				link()
			}
		}
		return e
	}
	if link() == nil {
		t.Fatalf("constructing the first link: %v", <-cerrs)
	}
	t.Cleanup(func() {
		stop.Store(true)
		_, _ = WipeAll(context.Background())
	})

	r := sweepAsync(t, context.Background(),
		"a constructor that never stops kept a context.Background sweep running; late registrations "+
			"must be tried, never waited for, and never earn another pass")

	select {
	case err := <-cerrs:
		t.Fatalf("a link failed to construct, so the chain stopped by itself: %v", err)
	default:
	}
	if made.Load() == 0 {
		t.Fatal("no link was constructed during the sweep; the test raced nothing")
	}
	if r.err != nil {
		t.Errorf("WipeAll err = %v, want nil", r.err)
	}
	if n := liveCount(); n != r.n {
		t.Errorf("WipeAll = %d but the ledger holds %d: the count is not the ledger", r.n, n)
	}
	if r.n != 1 {
		t.Errorf("WipeAll = %d, want 1: exactly one late link is left, registered by the last reclamation", r.n)
	}

	stop.Store(true)
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll after the chain stopped = %d, want 0", remaining)
	}
}

// TestWipeAll_TerminatesAgainstALiveConstructorUnderBackground pins the same
// guarantee against a real goroutine that constructs and borrows in a loop. A
// trigger enclave's release, inside the sweep after its first snapshot,
// requests a construction and waits for it to register, so at least one
// registration provably lands after the snapshot. Every construction must
// succeed, or the test proves nothing.
func TestWipeAll_TerminatesAgainstALiveConstructorUnderBackground(t *testing.T) {
	requireCleanLedger(t)

	// want carries a request for one construction; the goroutine answers on
	// the request's channel once that enclave is REGISTERED (the constructor
	// has returned), before it is borrowed.
	want := make(chan chan *Memory)
	cerr := make(chan error, 1)
	stop := make(chan struct{})
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var once sync.Once
		for {
			var ack chan *Memory
			select {
			case <-stop:
				return
			case ack = <-want:
			default:
			}
			e, err := newMemorySized(32)
			if err != nil {
				cerr <- err
				return
			}
			if ack != nil {
				ack <- e // registered: NewMemorySized publishes before returning
			}
			_ = e.WithBytes(func(b []byte) error {
				b[0] = 0x5A
				return nil
			})
			// Only the acknowledged enclave is left for the sweep to find;
			// every other one is returned at once, so the loop holds a
			// constant number of locked pages however long it spins.
			if ack == nil {
				_ = e.Destroy()
			}
			once.Do(func() { close(started) })
		}
	}()
	stopped := false
	stopConstructor := func() {
		if !stopped {
			stopped = true
			close(stop)
			<-done
		}
	}
	t.Cleanup(stopConstructor)

	select {
	case <-started:
	case err := <-cerr:
		t.Fatalf("the constructor failed before the sweep began: %v", err)
	}

	trigger, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	var lateRegistrations atomic.Int64
	trigger.release = func() {
		// Inside the sweep, after its first snapshot: ask the live goroutine
		// for a construction and wait until it is registered. A constructor
		// failure releases the sweep and is reported below.
		ack := make(chan *Memory, 1)
		select {
		case want <- ack:
		case err := <-cerr:
			cerr <- err
			return
		}
		select {
		case <-ack:
			lateRegistrations.Add(1)
		case err := <-cerr:
			cerr <- err
		}
	}

	r := sweepAsync(t, context.Background(),
		"a goroutine constructing and borrowing in a loop kept a context.Background sweep running")
	if r.err != nil {
		t.Errorf("WipeAll err = %v, want nil", r.err)
	}
	if lateRegistrations.Load() == 0 {
		select {
		case err := <-cerr:
			t.Fatalf("the live constructor failed during the sweep: %v", err)
		default:
		}
		t.Fatal("no enclave was registered by the live goroutine during the sweep; the test raced nothing")
	}

	stopConstructor()
	select {
	case err := <-cerr:
		t.Fatalf("the live constructor failed: %v", err)
	default:
	}
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll after the constructor stopped = %d, want 0", remaining)
	}
}

// TestWipeAll_ALateBorrowIsNeverWaitedFor pins that an enclave registered and
// borrowed during the sweep is not owed, so even under Background it is counted
// and left alone. The borrow starts from inside the sweep, so the next pass is
// certain to find it held.
func TestWipeAll_ALateBorrowIsNeverWaitedFor(t *testing.T) {
	requireCleanLedger(t)

	trigger, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	var (
		late   *Memory
		endMu  sync.Mutex
		endFn  func()
		lateOK = make(chan error, 1)
	)
	trigger.release = func() {
		e, cerr := newMemorySized(32)
		if cerr != nil {
			lateOK <- cerr
			return
		}
		late = e
		end := holdBorrow(t, e)
		endMu.Lock()
		endFn = end
		endMu.Unlock()
		lateOK <- nil
	}

	var waits atomic.Int32
	swapSeam(t, &sweepWaitingForTest, func() { waits.Add(1) })

	r := sweepAsync(t, context.Background(),
		"the sweep waited for a borrow on an enclave registered after it began; only owed entries are waited for")
	if err := <-lateOK; err != nil {
		t.Fatalf("constructing the late enclave: %v", err)
	}
	if r.n != 1 || r.err != nil {
		t.Errorf("WipeAll = (%d, %v), want (1, nil): the late, borrowed enclave is counted", r.n, r.err)
	}
	if got := waits.Load(); got != 0 {
		t.Errorf("the sweep blocked in its wait %d times, want 0: nothing it owed was held", got)
	}
	if !late.IsAlive() {
		t.Error("the late enclave was destroyed underneath its borrow")
	}

	endMu.Lock()
	end := endFn
	endMu.Unlock()
	end()
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll after the late borrow ended = %d, want 0", remaining)
	}
}

// TestWipeAll_RetriesAContendedLockAtOnce pins the tryContended branch: a
// TryLock that fails with a zero holder count has nobody to wake the sweep, so
// it retries at once. The test takes the read lock directly, bypassing the
// count, and lets go in the second pass, which exists only if the first retried.
func TestWipeAll_RetriesAContendedLockAtOnce(t *testing.T) {
	requireCleanLedger(t)

	e, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	e.mu.RLock() // uncounted on purpose: see the comment above
	var unlockOnce sync.Once
	unlock := func() { unlockOnce.Do(e.mu.RUnlock) }
	t.Cleanup(unlock)

	var passes, waits atomic.Int32
	swapSeam(t, &sweepPassForTest, func(pass int) {
		passes.Store(int32(pass))
		if pass == 2 {
			unlock()
		}
	})
	swapSeam(t, &sweepWaitingForTest, func() { waits.Add(1) })

	r := sweepAsync(t, context.Background(),
		"the sweep waited on a contended lock that no holder would ever announce")
	if r.n != 0 || r.err != nil {
		t.Errorf("WipeAll = (%d, %v), want (0, nil)", r.n, r.err)
	}
	if got := waits.Load(); got != 0 {
		t.Errorf("the sweep blocked in its wait %d times on a contended lock, want 0", got)
	}
	if got := passes.Load(); got < 2 {
		t.Errorf("the sweep made %d passes, want at least 2: the contended first pass was not retried", got)
	}
	if e.IsAlive() {
		t.Error("the enclave survived once its lock was free")
	}
}

// TestTryReleaseMapping_ClassifiesTheLock pins the three outcomes the sweep
// acts on, each against the lock state that produces it.
func TestTryReleaseMapping_ClassifiesTheLock(t *testing.T) {
	newEnclave := func(t *testing.T) *Memory {
		t.Helper()
		e, err := newMemorySized(32)
		if err != nil {
			t.Fatalf("NewMemorySized: %v", err)
		}
		t.Cleanup(func() { _ = e.Destroy() })
		return e
	}

	t.Run("a counted reader is held", func(t *testing.T) {
		e := newEnclave(t)
		e.rlock()
		got, err := e.tryRelease()
		e.runlock()
		if got != tryHeld || err != nil {
			t.Errorf("tryRelease = (%d, %v), want (tryHeld, nil)", got, err)
		}
	})
	t.Run("a counted writer is held", func(t *testing.T) {
		e := newEnclave(t)
		e.lock()
		got, err := e.tryRelease()
		e.unlock()
		if got != tryHeld || err != nil {
			t.Errorf("tryRelease = (%d, %v), want (tryHeld, nil)", got, err)
		}
	})
	t.Run("an uncounted lock is contended", func(t *testing.T) {
		e := newEnclave(t)
		e.mu.RLock()
		got, err := e.tryRelease()
		e.mu.RUnlock()
		if got != tryContended || err != nil {
			t.Errorf("tryRelease = (%d, %v), want (tryContended, nil)", got, err)
		}
	})
	t.Run("a free lock is released", func(t *testing.T) {
		e := newEnclave(t)
		got, err := e.tryRelease()
		if got != tryReleased || err != nil {
			t.Errorf("tryRelease = (%d, %v), want (tryReleased, nil)", got, err)
		}
		if e.IsAlive() {
			t.Error("a released enclave still reports alive")
		}
	})
}

// drainWake empties the wake slot and reports whether it held a wake-up.
func drainWake() bool {
	select {
	case <-sweepWake:
		return true
	default:
		return false
	}
}

// TestHolders_TheLastReleaseWakesOnlyAnArmedSweep pins the borrow side of the
// handshake: outside a sweep a release posts nothing, inside one only the
// release that takes the count to zero does, and wake-ups coalesce in the
// one-slot channel rather than blocking a releaser.
func TestHolders_TheLastReleaseWakesOnlyAnArmedSweep(t *testing.T) {
	e, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	t.Cleanup(func() {
		sweepWaiting.Store(false)
		drainWake()
		_ = e.Destroy()
	})
	drainWake()

	e.rlock()
	e.runlock()
	if drainWake() {
		t.Error("a release outside any sweep posted a wake-up; the borrow path must cost one load and nothing else there")
	}

	sweepWaiting.Store(true)
	e.rlock()
	e.rlock()
	e.runlock()
	if drainWake() {
		t.Error("a release that left another holder posted a wake-up; the sweep cannot take the lock yet")
	}
	e.runlock()
	if !drainWake() {
		t.Error("the last release under an armed sweep posted no wake-up: a waiting sweep would never hear it")
	}

	// Coalescing: two releases with nobody draining in between must neither
	// block nor queue two wake-ups.
	e.rlock()
	e.runlock()
	e.lock()
	e.unlock()
	if !drainWake() {
		t.Error("no wake-up pending after two armed releases")
	}
	if drainWake() {
		t.Error("two wake-ups were queued; they must coalesce into the one slot")
	}
}

// TestHolders_EveryMethodLeavesTheCountBalanced pins that every acquisition on
// Memory is bracketed, including a borrow whose callback panics: a count
// stuck above zero makes a Background sweep wait forever, one below zero lets
// it wait with no holder to wake it.
func TestHolders_EveryMethodLeavesTheCountBalanced(t *testing.T) {
	e, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	errBoom := errors.New("callback failed")

	for _, tc := range []struct {
		name string
		call func()
	}{
		{"WithBytes", func() { _ = e.WithBytes(func([]byte) error { return nil }) }},
		{"WithBytes returning an error", func() { _ = e.WithBytes(func([]byte) error { return errBoom }) }},
		{"WithBytes panicking", func() { _ = panicValue(func() { _ = e.WithBytes(func([]byte) error { panic(errBoom) }) }) }},
		{"EqualTo", func() { _ = holds(e, []byte("x")) }},
		{"Size", func() { _ = e.Size() }},
		{"IsAlive", func() { _ = e.IsAlive() }},
		{"String", func() { _ = e.String() }},
		{"Freeze", func() { _ = e.Freeze() }},
		{"Destroy", func() { _ = e.Destroy() }},
		{"Destroy again", func() { _ = e.Destroy() }},
		{"WithBytes after Destroy", func() { _ = e.WithBytes(func([]byte) error { return nil }) }},
	} {
		tc.call()
		if got := e.holders.Load(); got != 0 {
			t.Fatalf("%s left the holder count at %d, want 0", tc.name, got)
		}
	}
}

// TestDestroy_NilAndRepeatedReturnNil pins the deferable half of Destroy's
// contract: a nil enclave and an already-destroyed one have nothing to
// release, and report nothing.
func TestDestroy_NilAndRepeatedReturnNil(t *testing.T) {
	var nilEnclave *Memory
	if err := nilEnclave.Destroy(); err != nil {
		t.Errorf("Destroy on a nil enclave = %v, want nil", err)
	}

	e, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	if err := e.Destroy(); err != nil {
		t.Fatalf("Destroy = %v, want nil", err)
	}
	if err := e.Destroy(); err != nil {
		t.Errorf("a second Destroy = %v, want nil", err)
	}
}

// TestSweepError_ContractTable pins SweepError's methods field by field: which
// sentinels it matches, the text it renders, and that a zero field never
// matches its sentinel.
func TestSweepError_ContractTable(t *testing.T) {
	for _, tc := range []struct {
		name          string
		e             *SweepError
		wantCorrupt   bool
		wantUnwiped   bool
		wantFragments []string
	}{
		{
			name:        "corruption only",
			e:           &SweepError{Corrupt: 3},
			wantCorrupt: true,
			wantFragments: []string{
				"enclave: 3 of the swept enclaves failed canary verification: " + ErrEnclaveCorrupted.Error(),
			},
		},
		{
			name:        "unwiped only",
			e:           &SweepError{Unwiped: 2},
			wantUnwiped: true,
			wantFragments: []string{
				"enclave: 2 of the swept enclaves were unmapped without an in-process wipe because mprotect " +
					"was denied: " + ErrReleasedWithoutWipe.Error(),
			},
		},
		{
			name:        "both",
			e:           &SweepError{Corrupt: 1, Unwiped: 4},
			wantCorrupt: true,
			wantUnwiped: true,
			wantFragments: []string{
				"enclave: 1 of the swept enclaves failed canary verification: ",
				"\nenclave: 4 of the swept enclaves were unmapped without an in-process wipe",
			},
		},
		{
			name:          "neither",
			e:             &SweepError{},
			wantFragments: []string{"enclave: sweep reported nothing"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var err error = tc.e
			if got := errors.Is(err, ErrEnclaveCorrupted); got != tc.wantCorrupt {
				t.Errorf("errors.Is(%+v, ErrEnclaveCorrupted) = %v, want %v", tc.e, got, tc.wantCorrupt)
			}
			if got := errors.Is(err, ErrReleasedWithoutWipe); got != tc.wantUnwiped {
				t.Errorf("errors.Is(%+v, ErrReleasedWithoutWipe) = %v, want %v", tc.e, got, tc.wantUnwiped)
			}
			if errors.Is(err, ErrEnclaveDestroyed) {
				t.Errorf("errors.Is(%+v, ErrEnclaveDestroyed) = true; a sweep report matches only its own sentinels", tc.e)
			}
			for _, f := range tc.wantFragments {
				if !strings.Contains(err.Error(), f) {
					t.Errorf("Error() = %q, want it to contain %q", err.Error(), f)
				}
			}
			var se *SweepError
			if !errors.As(err, &se) || se != tc.e {
				t.Errorf("errors.As did not recover the *SweepError")
			}
		})
	}
}

// TestWipeAll_SweepErrorCountsAreReadableWithErrorsAs pins that WipeAll returns
// a *SweepError reachable with errors.As, with zero in the unused field.
func TestWipeAll_SweepErrorCountsAreReadableWithErrorsAs(t *testing.T) {
	requireCleanLedger(t)

	const total, corrupt = 4, 2
	for i := 0; i < total; i++ {
		e, err := newMemorySized(64)
		if err != nil {
			t.Fatalf("NewMemorySized: %v", err)
		}
		if i < corrupt {
			if len(e.m.canary) == 0 {
				t.Fatal("no canary slack at this size; the test would be vacuous")
			}
			e.m.canary[0] ^= 0xFF
		}
	}

	remaining, err := WipeAll(context.Background())
	if remaining != 0 {
		t.Errorf("WipeAll = %d, want 0: corrupt enclaves are still released", remaining)
	}
	var se *SweepError
	if !errors.As(err, &se) {
		t.Fatalf("WipeAll err = %v (%T), want a *SweepError", err, err)
	}
	if se.Corrupt != corrupt || se.Unwiped != 0 {
		t.Errorf("SweepError = %+v, want {Corrupt:%d Unwiped:0}", *se, corrupt)
	}
	if errors.Is(err, ErrReleasedWithoutWipe) {
		t.Error("the sweep error matches ErrReleasedWithoutWipe although no wipe was skipped")
	}
}

// parkSweepOnABorrow starts a context.Background sweep that parks waiting for
// a borrow on e that never ends until the returned end is called. It returns
// once the sweep is inside its wait, and a channel carrying the sweep's result.
func parkSweepOnABorrow(t *testing.T, e *Memory) (end func(), result <-chan sweepResult) {
	t.Helper()
	end = holdBorrow(t, e)
	parked := make(chan struct{})
	var once sync.Once
	swapSeam(t, &sweepWaitingForTest, func() { once.Do(func() { close(parked) }) })

	out := make(chan sweepResult, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		n, err := WipeAll(context.Background())
		out <- sweepResult{n, err}
	}()
	// Waits for the sweep to RETURN, not for its result, which the test may
	// already have taken.
	t.Cleanup(func() {
		end()
		<-finished
	})
	<-parked
	return end, out
}

// TestWipeAll_AParkedSweepDoesNotHoldASecondCallerHostage pins that admission
// honors the caller's ctx. Sweep A parks under Background on a live borrow;
// sweep B with a canceled, later-canceled, or nil ctx must return the ledger
// count and ErrSweepInProgress before the borrow ends. A still finishes.
func TestWipeAll_AParkedSweepDoesNotHoldASecondCallerHostage(t *testing.T) {
	requireCleanLedger(t)

	e, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	end, aResult := parkSweepOnABorrow(t, e)

	check := func(t *testing.T, name string, r sweepResult) {
		t.Helper()
		if !errors.Is(r.err, ErrSweepInProgress) {
			t.Errorf("%s: WipeAll err = %v, want ErrSweepInProgress: this call swept nothing", name, r.err)
		}
		if r.n != 1 {
			t.Errorf("%s: WipeAll = %d, want 1: the borrowed enclave is still held", name, r.n)
		}
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	check(t, "already canceled", sweepAsync(t, canceled,
		"a canceled context queued behind a parked sweep"))

	var nilCtx context.Context
	check(t, "nil", sweepAsync(t, nilCtx, "a nil context queued behind a parked sweep"))

	waiting, cancelWaiting := context.WithCancel(context.Background())
	defer cancelWaiting()
	var admissionWaits atomic.Int32
	swapSeam(t, &sweepAdmissionWaitForTest, func() {
		admissionWaits.Add(1)
		cancelWaiting()
	})
	check(t, "canceled while waiting", sweepAsync(t, waiting,
		"a context canceled while waiting for admission did not release the caller"))
	if got := admissionWaits.Load(); got != 1 {
		t.Errorf("the second caller waited for admission %d times, want 1", got)
	}

	if !e.IsAlive() {
		t.Error("the borrowed enclave was destroyed while its borrow was live")
	}
	if g := sweepGeneration(); !sweepInFlight(g) {
		t.Errorf("sweep generation %d is even while A is still sweeping: a refused caller touched the parity", g)
	}

	end()
	select {
	case r := <-aResult:
		if r.n != 0 || r.err != nil {
			t.Errorf("sweep A = (%d, %v) after the borrow ended, want (0, nil)", r.n, r.err)
		}
	case <-time.After(sweepHangBound):
		t.Fatal("sweep A did not finish after the borrow it waited for ended")
	}
	if g := sweepGeneration(); sweepInFlight(g) {
		t.Errorf("sweep generation %d is odd after every sweep returned", g)
	}
}

// TestWipeAll_ContentionRetriesHonorCtx pins that the immediate retry of a
// contended lock is not a loop around the context. The lock is held
// uncounted for the whole sweep, so every pass is contention-only; a sweep
// that retried without consulting ctx would never return. Canceling ctx at
// the third pass must end it, and a nil ctx must make no contention retry at
// all.
func TestWipeAll_ContentionRetriesHonorCtx(t *testing.T) {
	requireCleanLedger(t)

	e, err := newMemorySized(32)
	if err != nil {
		t.Fatalf("NewMemorySized: %v", err)
	}
	e.mu.RLock() // uncounted: every TryLock fails with holders at zero
	var unlockOnce sync.Once
	unlock := func() { unlockOnce.Do(e.mu.RUnlock) }
	t.Cleanup(unlock)

	var passes atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	swapSeam(t, &sweepPassForTest, func(pass int) {
		passes.Store(int32(pass))
		if pass == 3 {
			cancel()
		}
	})

	r := sweepAsync(t, ctx, "contention retries ignored a canceled context")
	if r.n != 1 || r.err != nil {
		t.Errorf("WipeAll = (%d, %v), want (1, nil): the contended enclave is still held", r.n, r.err)
	}
	if got := passes.Load(); got != 3 {
		t.Errorf("the sweep made %d passes, want 3: it retried at once until ctx ended, then stopped", got)
	}

	passes.Store(0)
	var nilCtx context.Context
	r = sweepAsync(t, nilCtx, "contention retries ignored a nil context")
	if r.n != 1 || r.err != nil {
		t.Errorf("WipeAll(nil) = (%d, %v), want (1, nil)", r.n, r.err)
	}
	if got := passes.Load(); got != 1 {
		t.Errorf("WipeAll(nil) made %d passes, want 1: a nil ctx never retries contention", got)
	}
	if !e.IsAlive() {
		t.Error("the contended enclave was destroyed")
	}

	unlock()
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll after the lock was released = %d, want 0", remaining)
	}
}

// orphanCount reports how many failed constructions' mappings are on the
// orphan ledger.
func orphanCount() int {
	registryMu.Lock()
	defer registryMu.Unlock()
	return len(orphans)
}

// requireCleanLedger sweeps and fails the test unless nothing — no enclave and
// no orphan — is left held, so the counts a test asserts are its own.
func requireCleanLedger(t *testing.T) {
	t.Helper()
	if remaining := sweep(t); remaining != 0 {
		t.Fatalf("the process already holds %d unreclaimable entries; this test needs a clean ledger", remaining)
	}
}

// denyProtect refuses every mprotect made through the protectMemory seam until
// the returned func lifts it; t.Cleanup lifts it as well. Guard-page mprotects
// (protNoAccess) pass, so a constructor gets as far as its freeze.
//
// Failures are injected only through seams, never by handing the kernel a
// malformed range: VirtualProtect accepts ranges POSIX mprotect refuses.
func denyProtect(t *testing.T) (lift func()) {
	t.Helper()
	prev := protectMemory
	swapSeam(t, &protectMemory, func(b []byte, p protection) error {
		if p == protNoAccess {
			return prev(b, p)
		}
		return errors.New("mprotect denied by policy")
	})
	return func() { protectMemory = prev }
}

// denyProtectAndUnmap is denyProtect with the unmap refused too, so release
// has no way to return the pages: they stay mapped and locked. A copy
// constructor's freeze and its cleanup both fail under it.
func denyProtectAndUnmap(t *testing.T) (lift func()) {
	t.Helper()
	liftProtect := denyProtect(t)
	prev := swapSeam(t, &unmapMemory, func([]byte) error { return errors.New("munmap denied too") })
	return func() { liftProtect(); unmapMemory = prev }
}

// TestAllocator_New_FailedConstructionIsReclaimedByWipeAll pins that a
// construction whose freeze and cleanup were both refused leaves an orphan: a
// sweep under the refusal counts it and keeps the charge, a sweep after it
// lifts reclaims it and refunds once, and a further sweep refunds nothing.
func TestAllocator_New_FailedConstructionIsReclaimedByWipeAll(t *testing.T) {
	requireCleanLedger(t)
	a, err := newBudgetAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })
	restore := denyProtectAndUnmap(t)

	e, err := a.admitData(material())
	if err == nil {
		e.Destroy()
		t.Fatal("Allocator.New succeeded although its freeze was refused")
	}
	if !lockedPagesHeld(err) {
		t.Fatalf("lockedPagesHeld(%v) = false; the setup did not strand locked pages", err)
	}
	if got := orphanCount(); got != 1 {
		t.Fatalf("orphan ledger holds %d, want 1: the failed construction's pages are unreachable", got)
	}
	if used := a.InUse(); used != pageSize {
		t.Errorf("InUse = %d with the pages still locked, want %d", used, pageSize)
	}

	remaining, werr := WipeAll(context.Background())
	if remaining != 1 {
		t.Errorf("WipeAll = %d with the cleanup still refused, want 1: the orphan still holds its pages", remaining)
	}
	if werr != nil {
		t.Errorf("WipeAll error = %v, want nil: nothing was corrupt or released unwiped", werr)
	}
	if used := a.InUse(); used != pageSize {
		t.Errorf("InUse = %d after a sweep that could not reclaim the orphan, want %d", used, pageSize)
	}

	restore()
	remaining, werr = WipeAll(context.Background())
	if remaining != 0 {
		t.Errorf("WipeAll = %d once the refusal lifted, want 0", remaining)
	}
	if werr != nil {
		t.Errorf("WipeAll error = %v, want nil", werr)
	}
	if got := orphanCount(); got != 0 {
		t.Errorf("orphan ledger holds %d after the reclaiming sweep, want 0", got)
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after the orphan's pages went back, want 0", used)
	}

	if remaining := sweep(t); remaining != 0 {
		t.Errorf("a further WipeAll = %d, want 0", remaining)
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after a further sweep, want 0: the refund ran more than once", used)
	}
}

// TestAllocator_NewSized_UnlockedOrphanIsReclaimedWithoutASecondRefund pins
// the other refund arm: an mlock refused at the ceiling refunds at once, so the
// still-mapped orphan must carry no refund of its own.
func TestAllocator_NewSized_UnlockedOrphanIsReclaimedWithoutASecondRefund(t *testing.T) {
	requireCleanLedger(t)
	a, err := newBudgetAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })

	prevLock, prevUnmap := lockMemory, unmapMemory
	swapSeam(t, &lockMemory, func([]byte) error { return errors.New("mlock: cannot allocate memory") })
	swapSeam(t, &unmapMemory, func([]byte) error { return errors.New("munmap refused") })

	if _, err := a.NewSized(32); !pagesHeld(err) || lockedPagesHeld(err) {
		t.Fatalf("NewSized = %v, want pages held but not locked", err)
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after a construction that left nothing locked, want 0", used)
	}
	if got := orphanCount(); got != 1 {
		t.Fatalf("orphan ledger holds %d, want 1: the mapped pages are unreachable", got)
	}
	if remaining := sweep(t); remaining != 1 {
		t.Errorf("WipeAll = %d with the unmap still refused, want 1", remaining)
	}

	lockMemory, unmapMemory = prevLock, prevUnmap
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll = %d once the unmap is allowed, want 0", remaining)
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after the orphan was reclaimed, want 0: the charge was refunded twice", used)
	}
	if avail := a.Available(); avail != 4*pageSize {
		t.Errorf("Available = %d, want the budget of %d exactly", avail, 4*pageSize)
	}
}

// TestNewMemoryCopy_FailedConstructionIsReclaimedByWipeAll pins orphan
// reclamation for the unadmitted constructors, where no budget is involved.
func TestNewMemoryCopy_FailedConstructionIsReclaimedByWipeAll(t *testing.T) {
	requireCleanLedger(t)
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })
	restore := denyProtectAndUnmap(t)

	if _, err := newMemoryCopy(material()); !lockedPagesHeld(err) {
		t.Fatalf("NewMemoryCopy = %v, want locked pages held", err)
	}
	if got := orphanCount(); got != 1 {
		t.Fatalf("orphan ledger holds %d, want 1", got)
	}
	if remaining := sweep(t); remaining != 1 {
		t.Errorf("WipeAll = %d with the cleanup still refused, want 1", remaining)
	}

	restore()
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll = %d once the refusal lifted, want 0", remaining)
	}
	if got := orphanCount(); got != 0 {
		t.Errorf("orphan ledger holds %d after the reclaiming sweep, want 0", got)
	}
}

// TestWipeAll_ReclaimsALockedOrphanWhoseUnlockStaysRefused pins that a sweep's
// retry of a locked orphan goes on to the unmap when munlock is refused, as
// abandon does (munmap drops the lock with it).
func TestWipeAll_ReclaimsALockedOrphanWhoseUnlockStaysRefused(t *testing.T) {
	requireCleanLedger(t)
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })

	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	refused := func([]byte) error { return errors.New("refused") }
	swapSeam(t, &unlockMemory, refused)
	prevUnmap := swapSeam(t, &unmapMemory, refused)

	herr := m.abandon(errors.New("the step that failed"), true)
	if !lockedPagesHeld(herr) {
		t.Fatalf("abandon = %v, want locked pages held", herr)
	}
	refunds := 0
	adoptOrphan(herr, func() { refunds++ })
	if got := orphanCount(); got != 1 {
		t.Fatalf("orphan ledger holds %d, want 1", got)
	}

	// The unmap becomes available; munlock stays refused.
	unmapMemory = prevUnmap
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll = %d with the unmap available again, want 0: the release stopped at the "+
			"refused munlock and never tried the unmap that would have taken the lock with it", remaining)
	}
	if got := orphanCount(); got != 0 {
		t.Errorf("orphan ledger holds %d after the reclaiming sweep, want 0", got)
	}
	if refunds != 1 {
		t.Errorf("the kept charge was refunded %d times, want exactly once", refunds)
	}
}

// TestWipeAll_ReclaimsOrphansAddedConcurrently runs failing constructions on
// several goroutines while WipeAll sweeps, for the race detector, and checks
// the final accounting is exact. Each refusal is transient, so every orphan is
// reclaimable by whichever sweep reaches it.
//
// To not pass vacuously, every failure must be the orphan path's, and one
// worker waits until the concurrent sweeper has reclaimed an orphan. The wait
// is bounded by sweeps, not time: the second tick after the wait belongs to a
// sweep that started after the adoption, so three ticks without a reclaim fail.
func TestWipeAll_ReclaimsOrphansAddedConcurrently(t *testing.T) {
	requireCleanLedger(t)
	const workers, perWorker = 4, 16
	// Room for every construction's charge at once, so no failure below can be
	// a budget refusal instead of the orphan path under test.
	a, err := newBudgetAllocator(workers * perWorker * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })

	// reclaimed counts the ALLOWED wipe-enabling mprotects. A region's second
	// one only ever happens in a sweep's retry of an orphan, so this is the
	// number of orphan releases the sweeps reached.
	var reclaimed atomic.Int64
	firstReclaim := make(chan struct{})
	var firstReclaimOnce sync.Once

	prevProtect, prevUnmap := protectMemory, unmapMemory
	var mu sync.Mutex
	refusedOnce := make(map[*byte]struct{})
	swapSeam(t, &protectMemory, func(b []byte, p protection) error {
		if p == protReadOnly {
			return errors.New("mprotect denied by policy") // every freeze fails
		}
		if p == protNoAccess {
			return prevProtect(b, p) // guard pages at construction
		}
		mu.Lock()
		_, seen := refusedOnce[&b[0]]
		if seen {
			delete(refusedOnce, &b[0])
		} else {
			refusedOnce[&b[0]] = struct{}{}
		}
		mu.Unlock()
		if !seen {
			return errors.New("mprotect denied by policy")
		}
		reclaimed.Add(1)
		firstReclaimOnce.Do(func() { close(firstReclaim) })
		return prevProtect(b, p)
	})
	// The unmap is refused exactly while a region's wipe-enabling mprotect is:
	// the construction's fallback unmap fails, so the pages are stranded, and
	// the retry that was allowed its mprotect is allowed its unmap too.
	swapSeam(t, &unmapMemory, func(b []byte) error {
		mu.Lock()
		_, pending := refusedOnce[&b[0]]
		mu.Unlock()
		if pending {
			return errors.New("munmap denied too")
		}
		return prevUnmap(b)
	})

	var adopted atomic.Int64
	var waitedOnce atomic.Bool
	var wg sync.WaitGroup
	done := make(chan struct{})
	sweeperDone := make(chan struct{})
	swept := make(chan struct{}) // unbuffered: a tick reaches only a waiter
	go func() {
		defer close(sweeperDone)
		for {
			select {
			case <-done:
				return
			default:
				_, _ = WipeAll(context.Background())
				select {
				case swept <- struct{}{}:
				default:
				}
			}
		}
	}()
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				e, err := a.admitData(material())
				if err == nil {
					e.Destroy()
					t.Errorf("Allocator.New succeeded although every freeze is refused")
					continue
				}
				if !lockedPagesHeld(err) {
					t.Errorf("Allocator.New = %v, want a failure that left locked pages for the orphan "+
						"ledger; this failure never reached the path under test", err)
					continue
				}
				adopted.Add(1)
				// One worker, once, holds still until the concurrent sweeper has
				// reclaimed an orphan, or three sweeps have finished without one.
				// The sweeper loops until every worker is done, so this cannot
				// wait on anything that is not running.
				if waitedOnce.CompareAndSwap(false, true) {
					for ticks := 0; ticks < 3; {
						select {
						case <-firstReclaim:
							ticks = 3
						case <-swept:
							ticks++
						}
					}
				}
			}
		}()
	}
	wg.Wait()
	close(done)
	<-sweeperDone
	concurrent := reclaimed.Load()

	if got := adopted.Load(); got != workers*perWorker {
		t.Fatalf("%d of %d constructions stranded locked pages, want all of them", got, workers*perWorker)
	}
	if concurrent == 0 {
		t.Fatal("the concurrent sweeper reclaimed no orphan; only the final drain would have been tested")
	}
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll = %d after every refusal lifted, want 0", remaining)
	}
	if got := orphanCount(); got != 0 {
		t.Errorf("orphan ledger holds %d, want 0", got)
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after every orphan was reclaimed, want 0", used)
	}
}

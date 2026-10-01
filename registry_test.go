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

// sweepHangBound is the deadline every test sweep runs under. It is a HANG
// DETECTOR and nothing else: no passing test comes anywhere near it, because a
// sweep that is not waiting for a borrow never consults its context, and the
// tests that do hold a borrow across a sweep end it themselves. What it buys is
// the failure mode. A regression that made the sweep wait for something that
// never ends would otherwise hang until the go test timeout and die as a
// goroutine dump; under this bound it returns a non-zero count that the
// calling test names.
const sweepHangBound = 60 * time.Second

// sweep runs WipeAll and fails the test if it reports corruption. No test but
// the corruption ones should ever see a non-nil error, so routing every other
// call through here turns an unexpected canary failure into a named failure
// instead of an ignored second return value.
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

// TestWipeAll_DestroysEveryLiveEnclave is the property a shutdown path needs:
// after the sweep, nothing this package allocated is still holding material.
//
// It counts the ledger rather than trusting the return value alone, because a
// WipeAll that returned 0 while leaving enclaves registered would satisfy the
// return contract and none of the point.
func TestWipeAll_DestroysEveryLiveEnclave(t *testing.T) {
	const n = 8
	material := bytes.Repeat([]byte{0xC7}, 48)

	before := liveCount()

	held := make([]*MemoryEnclave, 0, n)
	for i := 0; i < n; i++ {
		e, err := NewMemoryEnclave(append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("NewMemoryEnclave: %v", err)
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
		if e.EqualTo(material) {
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

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
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
// the ledger. Without deregistration the map would grow for the life of the
// process — every enclave ever created, retained by the registry, which is a
// leak of exactly the kind this package exists to avoid.
func TestWipeAll_AlreadyDestroyedIsANoOp(t *testing.T) {
	before := liveCount()

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
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

// TestWipeAll_ABorrowThatOutlastsCtxIsCountedNotUnmapped is the design
// decision made visible, in the form #88 gave it.
//
// A borrow live at shutdown is a consumer ordering problem, and there are three
// things WipeAll could do about it: block on the enclave's lock until it
// returns, unmap underneath it, or wait for it to end as long as the caller
// allows and then leave it alone and report. Blocking on the lock cannot be
// abandoned when the caller's deadline passes. Unmapping underneath is what
// memguard's purge did and what issue #2 removed — it faults the borrower. So
// it waits for the borrow's end as an EVENT, bounded by ctx, and when ctx wins
// it skips and counts.
//
// The context is canceled from inside the sweep at the moment it starts to
// wait, through sweepWaitingForTest, so the test exercises the wait's ctx
// branch rather than the check before it — and needs no clock to get there.
// The un-borrowed enclave must still be reclaimed: one live borrow must not
// stop the whole sweep.
func TestWipeAll_ABorrowThatOutlastsCtxIsCountedNotUnmapped(t *testing.T) {
	material := bytes.Repeat([]byte{0x3C}, 40)

	borrowed, err := NewMemoryEnclave(append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	other, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
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
	sweepWaitingForTest = func() {
		waits.Add(1)
		cancel()
	}
	t.Cleanup(func() { sweepWaitingForTest = nil })

	swept := make(chan int, 1)
	go func() { n, _ := WipeAll(ctx); swept <- n }()

	var remaining int
	select {
	case remaining = <-swept:
	case <-time.After(sweepHangBound):
		// Not t.Fatal with the borrow still parked: Destroy would block on it.
		t.Fatal("WipeAll did not return after its context was canceled with a borrow in flight: " +
			"the wait is not bounded by ctx, which is the shutdown hang #88 exists to prevent")
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

// TestWipeAll_ReturnsTheAllocatorReservations checks the sweep settles the
// budget on the same terms Destroy does. An Allocator whose enclaves were wiped
// by WipeAll but never credited back would report its budget permanently
// consumed, which for a process that sweeps and continues is a slow leak of
// admission capacity rather than of memory.
func TestWipeAll_ReturnsTheAllocatorReservations(t *testing.T) {
	a, err := NewAllocator(8 * pageSize)
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
// live traffic. The registry is touched on every New and every Destroy, so it is
// the one piece of shared state on the allocation path; under -race this is
// where a missing lock shows.
//
// What it does NOT cover is whether a zero result was truthful — a sweep racing
// construction could return zero while a late enclave was alive, and a test that
// only sweeps again after the workers stop cannot see that (Codex, PR #20). That
// property is covered deterministically by
// TestWipeAll_DoesNotReturnZeroWhileAnEnclaveIsAlive, which injects the late
// registration at the exact moment rather than hoping for an interleaving. This
// test is for lock discipline under contention and nothing more.
//
// It pins the property that matters most about the registry's design: the
// sweep must not deadlock against Destroy, which takes the SAME lock to
// deregister. WipeAll snapshots the ledger and releases the lock before
// destroying anything for exactly that reason — holding it across the sweep
// self-deadlocks on the first enclave.
//
// The sweeper is deliberately NOT in the worker WaitGroup. It stops when the
// workers finish, so waiting on a group containing it would wait for a goroutine
// whose exit condition is that wait completing. (Measured: the first version of
// this test did exactly that and hung.)
func TestWipeAll_ConcurrentWithConstructionAndDestruction(t *testing.T) {
	const goroutines, iterations = 50, 100

	var workers sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < iterations; i++ {
				e, err := NewMemoryEnclaveSized(64)
				if err != nil {
					t.Errorf("NewMemoryEnclaveSized: %v", err)
					return
				}
				// A sweep may already have destroyed it; either outcome is
				// correct, and Destroy is a no-op on one the sweep took.
				_ = e.WithBytes(func([]byte) error { return nil })
				e.Destroy()
			}
		}()
	}

	stop := make(chan struct{})
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
		}
	}()

	workersDone := make(chan struct{})
	go func() {
		workers.Wait()
		close(workersDone)
	}()

	select {
	case <-workersDone:
	case <-time.After(60 * time.Second):
		close(stop)
		t.Fatal("construction and destruction did not drain within 60s alongside a running WipeAll: " +
			"they are deadlocked against the registry lock")
	}

	close(stop)
	select {
	case <-sweeperDone:
	case <-time.After(30 * time.Second):
		t.Fatal("WipeAll did not return within 30s after the workers finished")
	}

	if remaining := sweep(t); remaining != 0 {
		t.Errorf("final WipeAll = %d, want 0", remaining)
	}
	if got := liveCount(); got != 0 {
		t.Errorf("ledger holds %d after everything drained, want 0", got)
	}
}

// TestWipeAll_DoesNotReturnZeroWhileAnEnclaveIsAlive is the deterministic
// version of the race Codex found on PR #20: an enclave registered AFTER the
// sweep took its snapshot was never visited, and WipeAll could return zero while
// it was mapped and holding material. Zero is the one thing this function
// promises, so a false zero is a fail-open on the whole contract.
//
// The injection point is real rather than simulated, and needs no production
// seam. An Allocator-backed enclave carries a release closure that WipeAll
// invokes DURING the sweep, in the sweep's own goroutine, after the snapshot has
// been taken. Setting that field from an in-package test puts arbitrary code at
// exactly the moment the race requires — which is deterministic, unlike hoping a
// concurrent goroutine interleaves the right way.
//
// It also re-proves the lock discipline for free: registering from inside the
// sweep would deadlock instantly if WipeAll still held the registry lock while
// destroying.
func TestWipeAll_DoesNotReturnZeroWhileAnEnclaveIsAlive(t *testing.T) {
	if remaining := sweep(t); remaining != 0 {
		t.Skipf("the process already holds %d unwipeable enclaves; this test needs a clean ledger", remaining)
	}

	trigger, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}

	var (
		lateMu sync.Mutex
		late   *MemoryEnclave
	)
	// Runs inside WipeAll, after the snapshot that will never contain `late`.
	trigger.release = func() {
		e, cerr := NewMemoryEnclaveSized(32)
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

// TestWipeAll_ConcurrentWithAllocatorConstructionKeepsTheBudgetExact is the
// second race Codex found on PR #20, and it is about PUBLICATION ORDER.
//
// The constructors used to register the enclave themselves, which put it on the
// ledger before Allocator.New had installed the reservation callback. A sweep
// landing in that window read release while it was being assigned — a data race
// — and destroyed the enclave with release still nil: the pages went back to the
// kernel and the budget kept the charge. Nothing ever returns it, so an
// Allocator that sweeps and keeps running loses admission capacity for good.
//
// Two oracles, and they are NOT of equal strength — which is worth stating
// rather than leaving for someone to discover when one of them goes quiet:
//
//   - THE RACE DETECTOR is what catches the defect, on the unsynchronized read
//     of release against its assignment. Measured 8/8 against the defective
//     shape restored as a mutant, with the one-page payload below. The CI test
//     job runs -race, so this is the oracle that guards the tree.
//   - THE BUDGET assertion is an end-state check, not a second detector. It
//     pins that every reservation is settled exactly once when enclaves are
//     destroyed by two different parties at once — a real property, and the one
//     the defect would have broken — but on its own it only fires when a sweep
//     lands inside the window, so it is not what makes this test load-bearing.
//
// Two earlier revisions were built the other way round, and the cost is worth
// recording. To make the budget oracle reliable they widened the window with a
// large payload (1 MiB, then 512 KiB) and sampled it with a sweeper that spun
// without yielding. Both worked locally — including pinned to a single CPU — and
// both blew this test's own drain bound on the build runner, twice, while the
// rest of the suite merely ran slower. The payload was the expensive half: under
// -race, hundreds of megabytes of mlock churn in a memory-capped container is a
// different order of problem from slow CPU.
//
// The width turned out to be unnecessary. Race detection needs the window
// ENTERED, not held open — a single page hits it just as reliably (8/8), for
// 1/128th of the memory and about a hundredth of the time. The strength that the
// big payload was buying belonged to the weaker oracle all along.
func TestWipeAll_ConcurrentWithAllocatorConstructionKeepsTheBudgetExact(t *testing.T) {
	const (
		goroutines = 4
		iterations = 25
		payload    = 4 << 10
		budget     = 8 << 20
	)

	a, err := NewAllocator(budget)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var swept, verified atomic.Int64
	var lockRefused atomic.Bool
	material := bytes.Repeat([]byte{0x5A}, payload)

	// Phase 1, QUIESCENT: a successful return is a usable enclave holding
	// exactly its material. This is checked with no sweeper running, because it
	// is a property of construction rather than of the race, and asserting it
	// against a live sweeper made it flaky in exactly the environments where the
	// sweeper wins most: on a single CPU the sweep took 99 of 100 enclaves, so
	// "at least one came back alive" failed while nothing was wrong.
	func() {
		e, err := a.New(append([]byte(nil), material...))
		if errors.Is(err, ErrLockedMemoryUnavailable) {
			lockRefused.Store(true)
			return
		}
		if err != nil {
			t.Fatalf("Allocator.New with no sweep running: %v", err)
		}
		defer e.Destroy()
		if !e.IsAlive() {
			t.Fatal("Allocator.New returned a destroyed enclave with no sweep running")
		}
		if !e.EqualTo(material) {
			t.Fatal("Allocator.New returned an enclave that does not hold its material")
		}
	}()
	if lockRefused.Load() {
		_, _ = WipeAll(context.Background())
		t.Skipf("the kernel refused to lock a %d-byte payload: RLIMIT_MEMLOCK is too low here "+
			"(a container default of 64 KiB will do this), and this test has to allocate to run at all",
			payload)
	}

	var workers sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < iterations; i++ {
				e, err := a.New(append([]byte(nil), material...))
				if errors.Is(err, ErrLockedMemoryUnavailable) {
					// A CI container with the classic 64 KiB RLIMIT_MEMLOCK
					// cannot lock a 1 MiB payload, and that is the environment
					// refusing, not a defect. Every other allocation test in this
					// package skips on this for the same reason; failing here
					// would turn a container default into a red build.
					lockRefused.Store(true)
					return
				}
				if err != nil {
					t.Errorf("Allocator.New: %v", err)
					return
				}
				// Give the sweeper a real turn before deciding who destroys
				// this one. Without it the caller always wins on a fast machine,
				// so the sweep-destroys-it branch below — the one where a lost
				// refund is permanent — never executes and the test proves half
				// of what it claims.
				//
				// A sleep rather than runtime.Gosched: Gosched yields to the
				// local run queue, so on a many-core host it can return before
				// the sweeper, parked on another P, has run at all. Measured:
				// with Gosched this tripped its own "the sweep never won a
				// single race" guard in 2 of 10 runs on a 24-core host, while
				// passing every time pinned to a single CPU. The sleep is a
				// small multiple of the sweeper's period, so the sweeper gets a
				// turn on any machine.
				//
				// KNOWN WEAK: this is a passive wait, and it guarantees nothing.
				// "A small multiple of the sweeper's period" is a scheduling hope,
				// not an ordering: on a loaded host the sweeper can still miss
				// every one of these windows, and the only thing standing between
				// that and a silently half-tested run is the swept == 0 guard at
				// the end, which turns it into a red build rather than a vacuous
				// green one. The active replacement is test-only (no production
				// seam is needed) — on some iterations hand the sweeper a reply
				// channel AFTER New returns and block until it closes it, which
				// makes the sweep-destroys-it branch certain rather than likely —
				// but it changes which interleavings the race detector gets to
				// see, so it has to be re-measured against the restored
				// publication-order mutant (8/8 above) before it lands. Tracked
				// in issue #83.
				time.Sleep(25 * time.Microsecond)

				if e.IsAlive() {
					if e.EqualTo(material) {
						verified.Add(1)
					}
					e.Destroy()
					continue
				}
				// The sweep already took it. Deliberately NOT destroyed: this
				// is the shutdown pattern where WipeAll owns the reclamation,
				// and it is the path on which a missing refund is permanent.
				swept.Add(1)
			}
		}()
	}

	stop := make(chan struct{})
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
			// Sleep rather than spin. An unbounded sweep loop is a hostile CI
			// citizen: on a shared or CPU-capped runner it burns the budget the
			// workers need and starves the very construction it is racing.
			// (Measured: the spinning version passed everywhere locally,
			// including pinned to one CPU, and blew its own drain bound on the
			// build runner.) The window this test aims at is entered once per
			// construction, so sweeping far more often than that buys nothing.
			//
			// KNOWN WEAK: this sleep is pacing, not synchronization, and pacing
			// by wall clock is exactly the thing that behaves differently on an
			// idle machine and a loaded one. The rate it is trying to express —
			// at most one sweep per construction — has an event to hang off: a
			// worker could post to a one-slot kick channel just before each
			// New, and this loop would block on that instead of the clock,
			// sweeping exactly as often as there is a window to land in and
			// burning nothing in between. Not done here because it is the same
			// redesign as the worker-side sleep above and needs the same
			// re-measurement against the mutant. Tracked in issue #83.
			time.Sleep(10 * time.Microsecond)
		}
	}()

	workersDone := make(chan struct{})
	go func() {
		workers.Wait()
		close(workersDone)
	}()

	select {
	case <-workersDone:
	case <-time.After(120 * time.Second):
		close(stop)
		t.Fatal("allocator-backed construction did not drain within 120s alongside a running WipeAll. " +
			"This test costs hundredths of a second on any machine measured; a bound this generous " +
			"being reached means it is blocked, not merely slow")
	}

	close(stop)
	select {
	case <-sweeperDone:
	case <-time.After(30 * time.Second):
		t.Fatal("WipeAll did not return within 30s after the workers finished")
	}

	if lockRefused.Load() {
		_, _ = WipeAll(context.Background())
		t.Skipf("the kernel refused to lock a %d-byte payload: RLIMIT_MEMLOCK is too low here "+
			"(a container default of 64 KiB will do this), and this test has to allocate to run at all",
			payload)
	}

	if remaining := sweep(t); remaining != 0 {
		t.Errorf("final WipeAll = %d, want 0", remaining)
	}
	t.Logf("%d of %d enclaves were destroyed by the sweep rather than by their caller; "+
		"%d came back alive and holding exactly their material",
		swept.Load(), goroutines*iterations, verified.Load())

	if swept.Load() == 0 {
		t.Error("the sweep never won a single race, so the branch where a lost refund would be " +
			"permanent was never executed and the budget assertion below proves nothing")
	}

	if got := a.InUse(); got != 0 {
		t.Errorf("InUse = %d after everything drained, want 0: a reservation was lost, which happens "+
			"when the sweep destroys an enclave whose release callback is not installed yet", got)
	}
	if got := a.Available(); got != budget {
		t.Errorf("Available = %d after everything drained, want the full budget %d", got, budget)
	}
}

// TestWipeAll_RetriesAReaderRatherThanAbandoningIt is the regression guard for
// the worst defect found on PR #20, and it is about the difference between
// "not right now" and "never".
//
// tryReleaseMapping takes the WRITE lock without waiting, so it loses to ANY
// concurrent reader — IsAlive, Size, EqualTo, a health probe polling an enclave
// during shutdown — not merely to a long WithBytes borrow. An earlier revision
// marked every enclave as seen when it built the pass's batch, before trying to
// release it, so one lost microsecond against a momentary reader took that
// enclave out of the sweep permanently: no later pass reconsidered it, the
// process exited with the material still mapped and locked, and WipeAll's own
// documentation blamed the caller's shutdown ordering. That is precisely the
// outcome this function exists to prevent, reached through its most ordinary
// concurrent operation.
//
// The reader here is released from INSIDE the sweep, through the release-closure
// injection point, and the sweep is made to WAIT until the read lock is actually
// dropped. That makes the handover synchronous instead of hoping a goroutine is
// scheduled inside a window of a few microseconds.
//
// THIS TEST IS HALF OF A PAIR — do not delete the other half. Its partner is
// TestWipeAll_ABorrowEndingWakesTheSweep. This one proves every pass
// reconsiders every still-registered enclave; that one proves the sweep WAITS
// for a held enclave's release rather than giving up on it. The promise that a
// momentary reader keeps its enclave needs BOTH, and neither test implies the
// other: this test passes with the wait deleted (reclaiming the gate earns the
// sweep its next pass, so it never has to wait), and its partner proves nothing
// about a pass that has other entries to reconsider. See that test's comment
// for the full decomposition.
//
// The scenario is repeated because ledger iteration is map-ordered: the defect
// only manifests when the sweep reaches the held enclave BEFORE the gate that
// frees it, which is a coin flip per trial. Over 16 trials the old behavior
// survives with probability 2^-16, while the fixed behavior passes every trial
// regardless of order.
func TestWipeAll_RetriesAReaderRatherThanAbandoningIt(t *testing.T) {
	if remaining := sweep(t); remaining != 0 {
		t.Skipf("the process already holds %d unwipeable enclaves; this test needs a clean ledger", remaining)
	}

	const trials = 16

	for trial := 0; trial < trials; trial++ {
		a, err := NewAllocator(16 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}

		// held is the enclave a reader is touching when the sweep arrives.
		held, err := NewMemoryEnclaveSized(64)
		if err != nil {
			t.Skipf("could not allocate: %v", err)
		}
		// gate runs code INSIDE the sweep, after the batch has been taken.
		gate, err := a.NewSized(64)
		if err != nil {
			held.Destroy()
			t.Skipf("could not allocate: %v", err)
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

		// Bounded, because the regression this guards against second-hardest is a
		// HANG: if tryReleaseMapping ever waited for the lock instead of trying
		// for it, WipeAll would block here forever behind the reader — and the
		// reader is only released from inside WipeAll, so nothing would ever break
		// the cycle. Without this the suite dies on the go test timeout with a
		// goroutine dump instead of a sentence. (Measured: a blocking-lock mutant
		// hung the whole package.)
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

// TestWipeAll_DoesNotPanicOnACorruptCanaryAndFinishesTheSweep pins the guarantee
// WipeAll's documentation makes most prominently and that nothing tested:
// it NEVER panics, including on an enclave whose canary fails.
//
// The guarantee is load-bearing in a specific way. Destroy panics on a detected
// corruption, deliberately — the caller cannot act on state that is by
// definition wrong. But a sweep is not one enclave: a panic partway through
// leaves every enclave the sweep had not reached yet mapped and holding
// material, which at process exit is the exact outcome WipeAll exists to
// prevent. So the corruption is counted and the sweep goes on, and a caller who
// needs to KNOW about it destroys that enclave itself.
//
// The corrupt enclave is placed in the middle of the batch, and the batch is
// checked in full: if the sweep aborted at the failure, the enclaves it had not
// reached would still be alive. (Ledger iteration is map-ordered, so "middle" is
// not a guarantee — checking all five is what makes the abort detectable
// regardless of the order the sweep happens to take.)
//
// A reservation is held too, because a corrupt canary must still settle the
// budget: the region WAS wiped and unmapped, and the error is a report about
// what already happened, so ErrEnclaveCorrupted counts as released on the same
// terms Destroy uses.
func TestWipeAll_DoesNotPanicOnACorruptCanaryAndFinishesTheSweep(t *testing.T) {
	if remaining := sweep(t); remaining != 0 {
		t.Skipf("the process already holds %d unwipeable enclaves; this test needs a clean ledger", remaining)
	}

	const count, corruptAt = 5, 2

	a, err := NewAllocator(16 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	held := make([]*MemoryEnclave, 0, count)
	for i := 0; i < count; i++ {
		// SIZED, so the pages stay writable and the canary can be corrupted from
		// here. A move-constructed enclave is frozen read-only and the write
		// below would fault instead — which is the freeze doing its job, and why
		// this hazard is documented as specific to sized enclaves.
		e, err := a.NewSized(64)
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
	// The corruption must be REPORTED. Non-fatal was the right call for a sweep;
	// invisible was not. Before this was a second return value, the one fact that
	// something wrote into memory it did not own vanished at exit behind a zero
	// that looked like success (Codex, PR #20).
	if sweepErr == nil {
		t.Error("WipeAll returned a nil error after detecting a corrupt canary: the memory was reclaimed " +
			"but the corruption was never reported, so a shutdown caller cannot tell a clean wipe from " +
			"detected memory corruption")
	}
	if sweepErr != nil && !errors.Is(sweepErr, ErrEnclaveCorrupted) {
		t.Errorf("WipeAll error = %v, want one matching ErrEnclaveCorrupted: callers match the sentinel, "+
			"exactly as they do on Destroy's panic value", sweepErr)
	}

	// And the corrupt enclave is NOT part of the count: its pages went back like
	// any other, so it is not still held. That is precisely why the corruption
	// needs a return value of its own.
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

// TestWipeAll_ReportsHowManyEnclavesWereCorrupt pins the other half of the
// corruption contract: the error carries the NUMBER, not merely the fact.
//
// One error is returned however many enclaves were corrupt. Joining N copies of
// a sentinel that has no per-enclave identity would repeat one sentence N times
// and tell an operator less than the count does — "3 of the swept enclaves
// failed canary verification" is the actionable form.
func TestWipeAll_ReportsHowManyEnclavesWereCorrupt(t *testing.T) {
	if remaining := sweep(t); remaining != 0 {
		t.Skipf("the process already holds %d unwipeable enclaves; this test needs a clean ledger", remaining)
	}

	const total, corruptCount = 5, 3

	for i := 0; i < total; i++ {
		e, err := NewMemoryEnclaveSized(64)
		if err != nil {
			t.Skipf("could not allocate: %v", err)
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

// TestWipeAll_ReportsCorruptionWhoseReleaseWasRefused pins the case where
// detecting corruption and reclaiming the pages are different attempts (#83).
// The sweep finds a failed canary, wipes, and is then refused the munmap: the
// enclave stays mapped, so it belongs in the count — and it is still corrupt,
// which the count cannot say. Before #83 the sweep only tallied corruption on
// the pass that reclaimed the pages, so a refusal that persisted for the whole
// sweep reported a clean nil.
//
// The figure in the message also pins that one enclave is counted once rather
// than once per attempt, and that needs a sweep that attempts it TWICE. Since
// #88 a sweep re-runs only when it reclaimed something it owed, so a companion
// enclave whose release is NOT refused rides along: whichever order the ledger
// is iterated in, reclaiming it earns a second pass, and the second pass
// retries the corrupt one — under strict unlock semantics, so that retry must
// also skip the unlock its predecessor already did (#83).
func TestWipeAll_ReportsCorruptionWhoseReleaseWasRefused(t *testing.T) {
	if remaining := sweep(t); remaining != 0 {
		t.Fatalf("the process already holds %d unwipeable enclaves; this test needs a clean ledger", remaining)
	}

	e, err := NewMemoryEnclaveSized(64)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	if len(e.m.canary) == 0 {
		t.Fatal("no canary slack at this size; the test would be vacuous")
	}
	e.m.canary[0] ^= 0xFF
	companion, err := NewMemoryEnclaveSized(64)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}

	prev := unmapMemory
	t.Cleanup(func() {
		unmapMemory = prev
		_, _ = WipeAll(context.Background())
	})
	installStrictUnlock(t)
	refused := &e.m.memory[0]
	var refusals atomic.Int32
	unmapMemory = func(b []byte) error {
		if &b[0] == refused {
			refusals.Add(1)
			return errors.New("munmap: cannot allocate memory")
		}
		return prev(b)
	}

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

// TestWipeAll_ReportsNoErrorWhenNothingIsCorrupt is the control for the two
// tests above. Without it they would pass against an implementation that
// reported corruption unconditionally, which is the failure mode of every
// assertion that only ever checks the interesting case.
func TestWipeAll_ReportsNoErrorWhenNothingIsCorrupt(t *testing.T) {
	if remaining := sweep(t); remaining != 0 {
		t.Skipf("the process already holds %d unwipeable enclaves; this test needs a clean ledger", remaining)
	}

	for i := 0; i < 4; i++ {
		if _, err := NewMemoryEnclaveSized(64); err != nil {
			t.Skipf("could not allocate: %v", err)
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

// TestWipeAll_AFailedReleaseKeepsBothTheChargeAndTheLedgerEntry covers the one
// path through WipeAll that nothing else reaches: an enclave whose release FAILS
// for a reason that is not corruption — the kernel refusing the mprotect,
// munlock or munmap.
//
// Two invariants meet on that path and neither is pinned without this:
//
//   - The Allocator charge must NOT be returned. The pages are still mapped, so
//     handing the budget back would let the allocator admit allocations the
//     process cannot satisfy — over-admission against a real RLIMIT_MEMLOCK.
//   - The enclave must STAY on the ledger, so it is counted as still-held and a
//     later sweep can retry it. Deregistering it would make WipeAll report zero
//     while the material is still mapped and locked, which is a fail-open on the
//     single guarantee the function makes.
//
// The failure is induced the way the release-path tests do it: the mprotect and
// the unmap are refused through their seams, leaving the real pages mapped.
func TestWipeAll_AFailedReleaseKeepsBothTheChargeAndTheLedgerEntry(t *testing.T) {
	if remaining, err := WipeAll(context.Background()); remaining != 0 || err != nil {
		t.Fatalf("this test needs a clean ledger; WipeAll = %d, %v", remaining, err)
	}

	a, err := NewAllocator(16 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.NewSized(64)
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
	// Still on the ledger and still charged -- both asserted directly, just
	// above -- and NOT alive. Inverted deliberately, for the reason in the
	// twin assertion in mapping_test.go: a.NewSized is mutable, so
	// wipeAndVerify's early wipe destroyed the material before the unmap that
	// failed. The retry the count is asking for still works, because it goes
	// through the mapping rather than the wiped flag (#13).
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

// TestWipeAll_ABorrowEndingWakesTheSweep pins the mechanism #88 put in place of
// the retry backoff: the end of a borrow WAKES a sweep that is waiting for it,
// and the enclave is reclaimed by that same call.
//
// The context is Background, deliberately. It never ends, so the only thing
// that can release the sweep from its wait is the wake-up the borrow's release
// posts. A sweep that missed it hangs, and the hang bound below turns that into
// a sentence. That is also what "promptly" means here, measured without a
// clock: the sweep waits exactly ONCE — it does not poll, and it does not need
// a second event — and returns having reclaimed the enclave.
//
// The borrow is ended only once the sweep has started to wait
// (sweepWaitingForTest), so this is the wake path and not the easier case of a
// borrow that ended before the sweep looked.
//
// # THIS TEST IS HALF OF A PAIR — do not delete the other half
//
// Its partner is TestWipeAll_RetriesAReaderRatherThanAbandoningIt. The
// user-facing promise — a momentary reader keeps its enclave — decomposes into
// two properties, and NEITHER test covers both:
//
//	(1) a held enclave is waited for, and the release that frees it ends the
//	    wait — this test
//	(2) every pass reconsiders every still-registered enclave
//	    — the partner, plus the visited-at-snapshot mutant
//
// Given both, a reader releasing at any point while ctx allows is reclaimed
// deductively. The predecessor of this test measured elapsed time against a
// fixed backoff budget; there is no budget left to measure, and an event is
// what is asserted instead.
func TestWipeAll_ABorrowEndingWakesTheSweep(t *testing.T) {
	if remaining := sweep(t); remaining != 0 {
		t.Fatalf("this test needs a clean ledger; WipeAll = %d", remaining)
	}

	e, err := NewMemoryEnclaveSized(64)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
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
	sweepWaitingForTest = func() {
		if waits.Add(1) == 1 {
			// The sweep has found the borrow held and is about to wait. End
			// the borrow now, from inside that window: the wake-up it posts is
			// the only thing that can end a Background wait.
			close(release)
			<-borrowDone
		}
	}
	t.Cleanup(func() { sweepWaitingForTest = nil })

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

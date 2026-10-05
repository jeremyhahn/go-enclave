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
	requireCleanLedger(t)

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
//     of release against its assignment. The CI test job runs -race, so this
//     is the oracle that guards the tree.
//   - THE BUDGET assertion is an end-state check, not a second detector. It
//     pins that every reservation is settled exactly once when enclaves are
//     destroyed by two different parties — a real property, and the one the
//     defect would have broken.
//
// # Every sweep is caused by an event, never by the clock (#90)
//
// Earlier revisions paced a free-running sweeper with time.Sleep and gave it
// "a turn" with a second sleep in each worker. Both were passive waits marked
// KNOWN WEAK: on a loaded host the sweeper could miss every window, and the
// only defense was a "the sweep never won" guard turning that into a red
// build. They are replaced by two events, each tied to what it is for:
//
//   - KICK, posted to a one-slot channel just BEFORE every construction, so
//     the sweeper runs one WipeAll per construction, concurrently with it.
//     That is the race-detector oracle's input: a sweep in flight while New
//     publishes. It costs nothing between constructions, unlike a sweeper
//     that spins or polls.
//   - SETTLE, a reply channel handed to the sweeper AFTER New returns on every
//     other iteration. The worker blocks until that sweep has finished, and
//     the sweep started after the enclave was published, so it CERTAINLY
//     destroyed it: the sweep-destroys-it branch — the one where a lost refund
//     is permanent — is exercised deterministically, half the iterations,
//     on any machine and any core count. The other half let the worker race
//     a kicked sweep for its own enclave, so both parties destroy enclaves.
//
// Measured against the restored publication-order mutant (register before the
// release callback is installed), -race, 20 runs at each of -cpu=1, 2 and 8:
// the race detector reports the release read/write race in every run.
//
// # Environment
//
// Allocates one 4 KiB payload per worker at a time, so at most a few pages are
// locked at once: the classic 64 KiB container RLIMIT_MEMLOCK is enough. A
// refused lock is a FAILURE, not a skip — the runner must provide that much
// locked memory (see the Test job in .github/workflows/ci.yml).
func TestWipeAll_ConcurrentWithAllocatorConstructionKeepsTheBudgetExact(t *testing.T) {
	requireCleanLedger(t)

	const (
		goroutines = 4
		iterations = 26
		payload    = 4 << 10
		budget     = 8 << 20
	)

	a, err := NewAllocator(budget)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var swept, settled, verified atomic.Int64
	material := bytes.Repeat([]byte{0x5A}, payload)

	// Phase 1, QUIESCENT: a successful return is a usable enclave holding
	// exactly its material. Checked with no sweeper running, because it is a
	// property of construction rather than of the race.
	func() {
		e, err := a.New(append([]byte(nil), material...))
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
	kick := make(chan struct{}, 1)
	settle := make(chan chan struct{})
	stop := make(chan struct{})
	sweeperDone := make(chan struct{})
	go func() {
		defer close(sweeperDone)
		for {
			select {
			case <-stop:
				return
			case <-kick:
				_, _ = WipeAll(context.Background())
			case reply := <-settle:
				_, _ = WipeAll(context.Background())
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
				// A sweep in flight while New publishes. Non-blocking: one
				// pending kick already guarantees the next sweep.
				select {
				case kick <- struct{}{}:
				default:
				}

				e, err := a.New(append([]byte(nil), material...))
				if err != nil {
					t.Errorf("Allocator.New: %v (ErrLockedMemoryUnavailable here means the runner's "+
						"RLIMIT_MEMLOCK cannot hold %d one-page enclaves at once — provision it)", err, goroutines)
					return
				}

				if i%2 == 0 {
					// Deterministic: a sweep that STARTS after New returned
					// finds the enclave on the ledger with nothing holding it,
					// and destroys it. The worker does not touch it again —
					// this is the shutdown pattern where WipeAll owns the
					// reclamation, and the path on which a missing refund is
					// permanent.
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
	requireCleanLedger(t)

	const trials = 16

	for trial := 0; trial < trials; trial++ {
		a, err := NewAllocator(16 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}

		// held is the enclave a reader is touching when the sweep arrives.
		held, err := NewMemoryEnclaveSized(64)
		if err != nil {
			t.Fatalf("trial %d: NewMemoryEnclaveSized: %v", trial, err)
		}
		// gate runs code INSIDE the sweep, after the batch has been taken.
		gate, err := a.NewSized(64)
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
// The guarantee is load-bearing in a specific way. A sweep is not one
// enclave: a panic partway through
// leaves every enclave the sweep had not reached yet mapped and holding
// material, which at process exit is the exact outcome WipeAll exists to
// prevent. So the corruption is counted and the sweep goes on.
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
	requireCleanLedger(t)

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
			"exactly as they do on Destroy's error", sweepErr)
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
	requireCleanLedger(t)

	const total, corruptCount = 5, 3

	for i := 0; i < total; i++ {
		e, err := NewMemoryEnclaveSized(64)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
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
	requireCleanLedger(t)

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
	requireCleanLedger(t)

	for i := 0; i < 4; i++ {
		if _, err := NewMemoryEnclaveSized(64); err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
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

// The tests from here on pin the lifecycle surface #88 introduced: WipeAll's
// event-driven wait and its context bound, the termination guarantee against a
// constructor that never stops, SweepError, and the holder handshake that makes
// the wait impossible to miss. None of them sleeps; every ordering is made by a
// channel or by a seam inside the sweep.

// holdBorrow starts a WithBytes borrow on e in its own goroutine and returns
// once it is inside the borrow. end finishes the borrow and waits for it to
// return; it is idempotent and also registered as cleanup, so a failing test
// never leaves the borrow parked.
func holdBorrow(t *testing.T, e *MemoryEnclave) (end func()) {
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

// TestWipeAll_ACanceledCtxStillSweepsWhatIsFree pins what an already-done
// context means: not a refusal, but "do not wait". Everything not currently
// held is reclaimed exactly as it would be under any other context, the held
// enclave is counted, and the sweep never enters its wait — the check before
// the wait decides, not a coin flip in a select between a pending wake-up and
// a closed done channel.
func TestWipeAll_ACanceledCtxStillSweepsWhatIsFree(t *testing.T) {
	requireCleanLedger(t)

	free, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	held, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	end := holdBorrow(t, held)

	var waits atomic.Int32
	sweepWaitingForTest = func() { waits.Add(1) }
	t.Cleanup(func() { sweepWaitingForTest = nil })

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

// TestWipeAll_ANilCtxNeverWaitsAndNeverPanics pins the documented treatment of
// a nil context: the same as an already-done one. A nil context in a shutdown
// path is a programming error, and the two other choices are both worse —
// dereferencing it breaks the never-panics promise, and treating it as
// Background turns the mistake into a shutdown that can hang.
func TestWipeAll_ANilCtxNeverWaitsAndNeverPanics(t *testing.T) {
	requireCleanLedger(t)

	free, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	held, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	end := holdBorrow(t, held)

	var waits atomic.Int32
	sweepWaitingForTest = func() { waits.Add(1) }
	t.Cleanup(func() { sweepWaitingForTest = nil })

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

// TestWipeAll_AConstructorThatNeverStopsCannotKeepTheSweepRunning is the
// termination guarantee, made deterministic.
//
// Every enclave in the chain constructs its successor from inside its own
// release, which WipeAll runs in the sweep's goroutine — so every reclamation
// registers something new, for as long as the test lets it. That is a
// constructor that never stops, racing the sweep at the worst possible moment,
// with no scheduler involved. Under context.Background a sweep that re-ran
// whenever it reclaimed anything would never return; the design's answer is
// that only entries the sweep OWES — present at its first pass — earn another
// pass, and late arrivals are tried but never extend it.
//
// The late link it leaves behind is counted, which is the truth: it is still
// held. The bound is what is under test, not a zero.
func TestWipeAll_AConstructorThatNeverStopsCannotKeepTheSweepRunning(t *testing.T) {
	requireCleanLedger(t)

	var (
		stop  atomic.Bool
		made  atomic.Int32
		cerrs = make(chan error, 1)
	)
	var link func() *MemoryEnclave
	link = func() *MemoryEnclave {
		e, err := NewMemoryEnclaveSized(32)
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

// TestWipeAll_TerminatesAgainstALiveConstructorUnderBackground is the same
// guarantee against a real goroutine: one constructing and borrowing enclaves
// in a loop, never destroying any, for the whole life of the sweep. Its
// enclaves are owed by the sweep only if they existed at its first pass, and
// the borrows on later ones are never waited for, so a context.Background
// sweep returns while the goroutine is still going.
//
// It is not allowed to pass vacuously. Every construction must succeed — a
// failure ends the goroutine and fails the test, since a constructor that
// stopped proves nothing about one that does not — and the sweep starts only
// after one has. A trigger enclave's release, which runs INSIDE the sweep after
// its first snapshot, then REQUESTS a construction from the live goroutine and
// waits for the acknowledgment the goroutine sends once that enclave is
// registered. The request is issued after the snapshot and the registration
// follows the request, so at least one registration provably lands after the
// sweep's first snapshot: one the sweep does not owe. (A counter of finished
// constructions cannot prove that: one registered before the snapshot and
// borrowed after it would advance the counter just the same.)
func TestWipeAll_TerminatesAgainstALiveConstructorUnderBackground(t *testing.T) {
	requireCleanLedger(t)

	// want carries a request for one construction; the goroutine answers on
	// the request's channel once that enclave is REGISTERED (the constructor
	// has returned), before it is borrowed.
	want := make(chan chan *MemoryEnclave)
	cerr := make(chan error, 1)
	stop := make(chan struct{})
	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		var once sync.Once
		for {
			var ack chan *MemoryEnclave
			select {
			case <-stop:
				return
			case ack = <-want:
			default:
			}
			e, err := NewMemoryEnclaveSized(32)
			if err != nil {
				cerr <- err
				return
			}
			if ack != nil {
				ack <- e // registered: NewMemoryEnclaveSized publishes before returning
			}
			_ = e.WithBytes(func(b []byte) error {
				b[0] = 0x5A
				return nil
			})
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

	trigger, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	var lateRegistrations atomic.Int64
	trigger.release = func() {
		// Inside the sweep, after its first snapshot: ask the live goroutine
		// for a construction and wait until it is registered. A constructor
		// failure releases the sweep and is reported below.
		ack := make(chan *MemoryEnclave, 1)
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

// TestWipeAll_ALateBorrowIsNeverWaitedFor pins the half of the termination rule
// that is about borrows rather than passes. An enclave that registers during the
// sweep and is borrowed is not owed, so even under context.Background the
// sweep does not wait for it: it is counted, and left alone.
//
// The late enclave is constructed and its borrow STARTED from inside the sweep
// (the first link's release), and the hook waits until the borrow is inside
// its callback before the sweep continues. So the sweep's next pass is certain
// to find it held.
func TestWipeAll_ALateBorrowIsNeverWaitedFor(t *testing.T) {
	requireCleanLedger(t)

	trigger, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	var (
		late   *MemoryEnclave
		endMu  sync.Mutex
		endFn  func()
		lateOK = make(chan error, 1)
	)
	trigger.release = func() {
		e, cerr := NewMemoryEnclaveSized(32)
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
	sweepWaitingForTest = func() { waits.Add(1) }
	t.Cleanup(func() { sweepWaitingForTest = nil })

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
// TryLock that fails while the holder count reads zero has nobody to wake the
// sweep later, so the sweep must retry at once rather than wait — waiting there
// is exactly the lost wake-up the holder count exists to rule out.
//
// Production cannot produce a contended lock on demand: every acquisition is
// counted, so this is a spurious TryLock failure or a holder that came and
// went between two reads. The test produces it by taking the read lock
// DIRECTLY, bypassing the count, and lets go from inside the sweep's second
// pass — which only exists if the first pass retried instead of waiting.
func TestWipeAll_RetriesAContendedLockAtOnce(t *testing.T) {
	requireCleanLedger(t)

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	e.mu.RLock() // uncounted on purpose: see the comment above
	var unlockOnce sync.Once
	unlock := func() { unlockOnce.Do(e.mu.RUnlock) }
	t.Cleanup(unlock)

	var passes, waits atomic.Int32
	sweepPassForTest = func(pass int) {
		passes.Store(int32(pass))
		if pass == 2 {
			unlock()
		}
	}
	sweepWaitingForTest = func() { waits.Add(1) }
	t.Cleanup(func() {
		sweepPassForTest = nil
		sweepWaitingForTest = nil
	})

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
	newEnclave := func(t *testing.T) *MemoryEnclave {
		t.Helper()
		e, err := NewMemoryEnclaveSized(32)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
		}
		t.Cleanup(func() { _ = e.Destroy() })
		return e
	}

	t.Run("a counted reader is held", func(t *testing.T) {
		e := newEnclave(t)
		e.rlock()
		got, err := e.tryReleaseMapping()
		e.runlock()
		if got != tryHeld || err != nil {
			t.Errorf("tryReleaseMapping = (%d, %v), want (tryHeld, nil)", got, err)
		}
	})
	t.Run("a counted writer is held", func(t *testing.T) {
		e := newEnclave(t)
		e.lock()
		got, err := e.tryReleaseMapping()
		e.unlock()
		if got != tryHeld || err != nil {
			t.Errorf("tryReleaseMapping = (%d, %v), want (tryHeld, nil)", got, err)
		}
	})
	t.Run("an uncounted lock is contended", func(t *testing.T) {
		e := newEnclave(t)
		e.mu.RLock()
		got, err := e.tryReleaseMapping()
		e.mu.RUnlock()
		if got != tryContended || err != nil {
			t.Errorf("tryReleaseMapping = (%d, %v), want (tryContended, nil)", got, err)
		}
	})
	t.Run("a free lock is released", func(t *testing.T) {
		e := newEnclave(t)
		got, err := e.tryReleaseMapping()
		if got != tryReleased || err != nil {
			t.Errorf("tryReleaseMapping = (%d, %v), want (tryReleased, nil)", got, err)
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
	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
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
// MemoryEnclave is bracketed: a count left above zero would make every later
// sweep think the enclave is held forever — under context.Background, a
// shutdown that never finishes — and one below zero would let a sweep wait
// with no holder left to wake it. A borrow whose callback panics is included,
// because the release is deferred and must still run.
func TestHolders_EveryMethodLeavesTheCountBalanced(t *testing.T) {
	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	errBoom := errors.New("callback failed")

	for _, tc := range []struct {
		name string
		call func()
	}{
		{"WithBytes", func() { _ = e.WithBytes(func([]byte) error { return nil }) }},
		{"WithBytes returning an error", func() { _ = e.WithBytes(func([]byte) error { return errBoom }) }},
		{"WithBytes panicking", func() { _ = panicValue(func() { _ = e.WithBytes(func([]byte) error { panic(errBoom) }) }) }},
		{"Open", func() { _, _ = e.Open() }},
		{"OpenString", func() { _, _ = e.OpenString() }},
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
	var nilEnclave *MemoryEnclave
	if err := nilEnclave.Destroy(); err != nil {
		t.Errorf("Destroy on a nil enclave = %v, want nil", err)
	}

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
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

// TestWipeAll_SweepErrorCountsAreReadableWithErrorsAs pins the error WipeAll
// actually returns: a *SweepError, reachable with errors.As, carrying the
// number of corrupt enclaves — and nothing in the field for a condition that
// did not happen.
func TestWipeAll_SweepErrorCountsAreReadableWithErrorsAs(t *testing.T) {
	requireCleanLedger(t)

	const total, corrupt = 4, 2
	for i := 0; i < total; i++ {
		e, err := NewMemoryEnclaveSized(64)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
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
func parkSweepOnABorrow(t *testing.T, e *MemoryEnclave) (end func(), result <-chan sweepResult) {
	t.Helper()
	end = holdBorrow(t, e)
	parked := make(chan struct{})
	var once sync.Once
	sweepWaitingForTest = func() { once.Do(func() { close(parked) }) }
	t.Cleanup(func() { sweepWaitingForTest = nil })

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

// TestWipeAll_AParkedSweepDoesNotHoldASecondCallerHostage is the regression
// for admission ignoring ctx (Codex on #95). Sweep A runs under
// context.Background and parks on a borrow that has not ended. Sweep B arrives
// with a context that is canceled, that is canceled while B waits for
// admission, or that is nil. Each must return before the borrow ends,
// reporting the ledger as it stands and ErrSweepInProgress, rather than
// queueing behind A for as long as A waits. A must still finish its sweep once
// the borrow ends.
func TestWipeAll_AParkedSweepDoesNotHoldASecondCallerHostage(t *testing.T) {
	requireCleanLedger(t)

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
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
	sweepAdmissionWaitForTest = func() {
		admissionWaits.Add(1)
		cancelWaiting()
	}
	t.Cleanup(func() { sweepAdmissionWaitForTest = nil })
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

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	e.mu.RLock() // uncounted: every TryLock fails with holders at zero
	var unlockOnce sync.Once
	unlock := func() { unlockOnce.Do(e.mu.RUnlock) }
	t.Cleanup(unlock)

	var passes atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sweepPassForTest = func(pass int) {
		passes.Store(int32(pass))
		if pass == 3 {
			cancel()
		}
	}
	t.Cleanup(func() { sweepPassForTest = nil })

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
// the returned func lifts it; t.Cleanup lifts it as well. Construction's
// guard-page mprotects (protNoAccess) pass, so a constructor gets as far as
// its freeze. The mapping keeps its
// real slices throughout, so nothing but the refusal differs from production.
//
// Failures are injected ONLY through the seams. An earlier helper handed the
// kernel a malformed range instead — the mapping's handle re-pointed at an
// unaligned probe slice — on the assumption that mprotect must refuse it. That
// holds for POSIX mprotect and not for VirtualProtect, which accepts a range
// crossing page boundaries: on Windows the probe was made writable and the
// release then touched the real mapping's still-inaccessible guard pages.
func denyProtect(t *testing.T) (lift func()) {
	t.Helper()
	prev := protectMemory
	lift = func() { protectMemory = prev }
	t.Cleanup(lift)
	protectMemory = func(b []byte, p protection) error {
		if p == protNoAccess {
			return prev(b, p)
		}
		return errors.New("mprotect denied by policy")
	}
	return lift
}

// denyProtectAndUnmap is denyProtect with the unmap refused too, which is
// every way release has of returning the pages: it cannot make the region
// writable, so it was not wiped by the mprotect path, and the unmap it falls
// back to is refused. The pages stay mapped AND locked. A copy constructor's
// freeze fails under it and so does its cleanup.
func denyProtectAndUnmap(t *testing.T) (lift func()) {
	t.Helper()
	liftProtect := denyProtect(t)
	prev := unmapMemory
	liftUnmap := func() { unmapMemory = prev }
	t.Cleanup(liftUnmap)
	unmapMemory = func([]byte) error { return errors.New("munmap denied too") }
	return func() { liftProtect(); liftUnmap() }
}

// TestAllocator_New_FailedConstructionIsReclaimedByWipeAll is the regression
// for the dropped-handle finding in #83, on the path that kept the charge.
//
// A construction whose freeze was refused, and whose cleanup was refused too,
// returned nil and an error and dropped the only reference to its mapping. The
// pages never reached the ledger, so no WipeAll could ever reclaim them — even
// after the refusal lifted — and the Allocator charge kept for those still-
// locked pages was kept for the process lifetime with nothing to return it.
//
// Asserted end to end: the failed construction leaves an orphan; a sweep with
// the refusal still in force counts it and keeps the charge; a sweep after the
// refusal lifts reclaims it, counts zero and returns the charge; and a further
// sweep returns nothing more, so the refund happened exactly once.
func TestAllocator_New_FailedConstructionIsReclaimedByWipeAll(t *testing.T) {
	requireCleanLedger(t)
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })
	restore := denyProtectAndUnmap(t)

	e, err := a.New(material())
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

// TestAllocator_NewSized_UnlockedOrphanIsReclaimedWithoutASecondRefund is the
// other refund arm. An mlock refused at the ceiling leaves nothing locked, so
// the constructor refunds at once — but when the unmap is refused the pages
// are still MAPPED, and they must reach the orphan ledger with NO refund of
// their own: a record carrying the charge as well would hand it back twice
// and take the budget past its limit.
func TestAllocator_NewSized_UnlockedOrphanIsReclaimedWithoutASecondRefund(t *testing.T) {
	requireCleanLedger(t)
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })

	prevLock, prevUnmap := lockMemory, unmapMemory
	restore := func() { lockMemory, unmapMemory = prevLock, prevUnmap }
	t.Cleanup(restore)
	lockMemory = func([]byte) error { return errors.New("mlock: cannot allocate memory") }
	unmapMemory = func([]byte) error { return errors.New("munmap refused") }

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

	restore()
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

// TestNewMemoryEnclaveCopy_FailedConstructionIsReclaimedByWipeAll is the
// unadmitted constructors' half: no budget is involved, but the stranded pages
// are locked memory all the same, and WipeAll's whole purpose is that none
// outlive the process unreported.
func TestNewMemoryEnclaveCopy_FailedConstructionIsReclaimedByWipeAll(t *testing.T) {
	requireCleanLedger(t)
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })
	restore := denyProtectAndUnmap(t)

	if _, err := NewMemoryEnclaveCopy(material()); !lockedPagesHeld(err) {
		t.Fatalf("NewMemoryEnclaveCopy = %v, want locked pages held", err)
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

// TestWipeAll_ReclaimsALockedOrphanWhoseUnlockStaysRefused pins the retry for
// an orphan that is still LOCKED (#83). A construction that locked its pages
// and then failed is rolled back by abandon, which carries on to the unmap when
// munlock is refused — munmap takes the lock with it. The sweep's retries must
// do the same. Until they did, a release that met the refused munlock returned
// before the unmap, so the orphan and the charge kept for it stayed held for
// as long as munlock stayed refused, however available the unmap became.
// TestAllocator_NewSized_UnlockedOrphanIsReclaimedWithoutASecondRefund cannot
// see this: its orphan never locked.
func TestWipeAll_ReclaimsALockedOrphanWhoseUnlockStaysRefused(t *testing.T) {
	requireCleanLedger(t)
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })

	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}

	prevUnlock, prevUnmap := unlockMemory, unmapMemory
	t.Cleanup(func() { unlockMemory, unmapMemory = prevUnlock, prevUnmap })
	refused := func([]byte) error { return errors.New("refused") }
	unlockMemory, unmapMemory = refused, refused

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
// several goroutines while WipeAll sweeps, for the race detector. Constructors
// add to the orphan ledger without the sweep slot; the sweep reads and drops records
// and runs their refunds. Every refusal here is transient — a region's first
// wipe-enabling mprotect is refused and its second allowed — so each orphan
// is reclaimable by whichever sweep reaches it, and the final accounting must
// come out exact.
//
// It must not pass vacuously, which an earlier revision could: it counted
// EVERY construction error, so a host whose real mlock refused first would
// fail every construction, refund normally, adopt nothing, and still pass. So
// each failure must be the orphan path's — locked pages held — and at least one
// orphan must be reclaimed by the CONCURRENT sweeper, not the final drain. That
// is made deterministic rather than hoped for: the first worker to strand a
// mapping waits until the sweeper has reclaimed one, while the other workers
// keep constructing.
//
// The wait is bounded by SWEEPS, not time, so a regression fails rather than
// hangs. The sweeper offers a tick after every WipeAll, which only a waiting
// worker can take; the second tick belongs to a sweep that STARTED after the
// wait did, and so after the adoption, and that sweep must have reclaimed the
// orphan. Three ticks without a reclaim is therefore a failure, not bad luck.
func TestWipeAll_ReclaimsOrphansAddedConcurrently(t *testing.T) {
	requireCleanLedger(t)
	const workers, perWorker = 4, 16
	// Room for every construction's charge at once, so no failure below can be
	// a budget refusal instead of the orphan path under test.
	a, err := NewAllocator(workers * perWorker * pageSize)
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
	t.Cleanup(func() { protectMemory, unmapMemory = prevProtect, prevUnmap })
	var mu sync.Mutex
	refusedOnce := make(map[*byte]struct{})
	protectMemory = func(b []byte, p protection) error {
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
	}
	// The unmap is refused exactly while a region's wipe-enabling mprotect is:
	// the construction's fallback unmap fails, so the pages are stranded, and
	// the retry that was allowed its mprotect is allowed its unmap too.
	unmapMemory = func(b []byte) error {
		mu.Lock()
		_, pending := refusedOnce[&b[0]]
		mu.Unlock()
		if pending {
			return errors.New("munmap denied too")
		}
		return prevUnmap(b)
	}

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
				e, err := a.New(material())
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

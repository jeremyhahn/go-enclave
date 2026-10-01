// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The tests in this file pin the lifecycle surface #88 introduced: WipeAll's
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
		{"EqualTo", func() { _ = e.EqualTo([]byte("x")) }},
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

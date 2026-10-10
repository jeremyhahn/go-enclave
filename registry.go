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
	"sync"
	"sync/atomic"
)

// The registry is a shutdown ledger for a cooperative sweep, not a fault
// handler: it is touched on construction, on destruction and by WipeAll, and
// never on the borrow path. See docs/shutdown-sweep/engineering.md.

// The sweep waits for a held enclave by event, not by sleeping. sweepWaiting
// is armed for a whole sweep; a lock holder reads it after letting go and only
// then calls wakeSweep (see memoryState.unhold). sweepWake holds at most one
// pending wake-up, so wake-ups coalesce and a sender never blocks. The sweep
// drains it at the start of every pass, before trying any lock, so no release
// is missed; the argument is on memoryState.holders.
var (
	sweepWaiting atomic.Bool
	sweepWake    = make(chan struct{}, 1)

	// sweepWaitingForTest runs when the sweep is about to block waiting for a borrow.
	sweepWaitingForTest func()

	// sweepPassForTest runs at the start of every pass, after the drain, with the pass ordinal from 1.
	sweepPassForTest func(pass int)
)

// wakeSweep posts a wake-up to a waiting sweep, dropping it if one is already
// pending. It never blocks and never allocates.
func wakeSweep() {
	select {
	case sweepWake <- struct{}{}:
	default:
	}
}

// rlock takes the read lock, counted in holders.
func (e *memoryState) rlock() {
	e.holders.Add(1)
	e.mu.RLock()
}

// runlock releases what rlock took.
func (e *memoryState) runlock() {
	e.mu.RUnlock()
	e.unhold()
}

// lock is rlock for the write lock: Freeze and Destroy.
func (e *memoryState) lock() {
	e.holders.Add(1)
	e.mu.Lock()
}

// unlock releases what lock took.
func (e *memoryState) unlock() {
	e.mu.Unlock()
	e.unhold()
}

// unhold decrements holders before reading sweepWaiting; reversing them loses
// wake-ups.
func (e *memoryState) unhold() {
	if e.holders.Add(-1) == 0 && sweepWaiting.Load() {
		wakeSweep()
	}
}

// tryOutcome is what tryRelease reports about the lock.
type tryOutcome uint8

const (
	// tryReleased: the lock was taken and a release attempted.
	tryReleased tryOutcome = iota
	// tryHeld: a holder will wake the sweep, so it may wait.
	tryHeld
	// tryContended: a spurious TryLock failure; retry, never wait.
	tryContended
)

// tryRelease is Destroy's release without waiting, for WipeAll only: a
// blocked Lock cannot be abandoned when ctx ends.
func (e *memoryState) tryRelease() (tryOutcome, error) {
	if !e.mu.TryLock() {
		// Read after the caller armed sweepWaiting.
		if e.holders.Load() != 0 {
			return tryHeld, nil
		}
		return tryContended, nil
	}
	defer e.mu.Unlock()
	return tryReleased, e.releaseLocked()
}

var (
	registryMu sync.Mutex
	// live holds every enclave constructed and not yet released.
	live = make(map[*memoryState]struct{})
	// orphans holds the mappings failed constructions could not give back,
	// each in an enclave no caller can reach, so the sweep releases it
	// exactly as it releases a live one.
	orphans = make(map[*memoryState]struct{})
	// corruptNoted holds entries whose release found a failed canary since
	// the last admitted sweep, which reports and clears them.
	corruptNoted = make(map[*memoryState]struct{})

	// sweepGen is a sequence lock behind [Sealed.Openable]'s fallback:
	// WipeAll bumps it before destroying anything and again on return, so an
	// odd value means a sweep is in flight. Monotonic, written only by WipeAll.
	sweepGen atomic.Uint64

	// sweepParkedForTest runs after the generation bump and before anything is destroyed.
	sweepParkedForTest func()

	// sweepSlot admits one WipeAll at a time, keeping sweepGen single-writer.
	// A channel rather than a mutex so a waiting caller can give up when its
	// own ctx ends. Taken before registryMu and never while holding it.
	sweepSlot = make(chan struct{}, 1)

	// sweepAdmissionWaitForTest runs when a sweep is about to block for the slot.
	sweepAdmissionWaitForTest func()
)

// admitSweep takes the sweep slot, waiting for it no longer than ctx allows.
// A free slot is taken even under a done ctx. A nil ctx only tries.
func admitSweep(ctx context.Context) bool {
	select {
	case sweepSlot <- struct{}{}:
		return true
	default:
	}
	if ctx == nil {
		return false
	}
	if sweepAdmissionWaitForTest != nil {
		sweepAdmissionWaitForTest()
	}
	select {
	case sweepSlot <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

// ledgerCount is how many entries still hold this package's pages, read under
// the ledger lock.
func ledgerCount() int {
	registryMu.Lock()
	defer registryMu.Unlock()
	return len(live) + len(orphans)
}

// adoptOrphan puts the mapping a failed construction's err carries onto the
// orphan ledger, with refund to run when a sweep releases it. It is a no-op
// when err left nothing mapped. Constructors call it after the refund
// decision is made, so a sweep never reaches an orphan without its refund.
func adoptOrphan(err error, refund func()) {
	var held *pagesHeldError
	if !errors.As(err, &held) || held.orphan == nil {
		return
	}
	o := &memoryState{m: held.orphan, release: refund}
	// One adoption per mapping, however often the error is passed around.
	held.orphan = nil

	registryMu.Lock()
	orphans[o] = struct{}{}
	registryMu.Unlock()
}

// register adds e to the shutdown ledger and returns its handle. It publishes
// e to a concurrent [WipeAll], so it must be the last step of construction, after
// every field a sweep reads (release in particular) is set; registryMu is the
// happens-before edge that makes them visible to the sweep.
func register(e *memoryState) *Memory {
	registryMu.Lock()
	live[e] = struct{}{}
	registryMu.Unlock()
	return &Memory{memoryState: e}
}

// settleRelease books the outcome err of a release attempt on the ledger entry
// e, live or orphan, and reports whether the pages went back. Only then does
// it return e's Allocator reservation (at most once) and drop e from the
// ledger; a detected corruption is noted either way, in the same step, so a
// sweep sees the entry or the note and the next WipeAll reports it even when
// the caller discarded err.
func settleRelease(e *memoryState, err error) bool {
	released := releasedPages(err)
	if released && e.release != nil {
		e.releaseOnce.Do(e.release)
	}

	registryMu.Lock()
	defer registryMu.Unlock()
	if errors.Is(err, ErrEnclaveCorrupted) {
		corruptNoted[e] = struct{}{}
	}
	if released {
		// e is on one ledger; deleting from the other is a no-op.
		delete(live, e)
		delete(orphans, e)
	}
	return released
}

// sweepGeneration reports the current sweep sequence. A sealed value records
// it before it seals; an odd value means a sweep was in flight.
func sweepGeneration() uint64 { return sweepGen.Load() }

// sweepInFlight reports whether g was taken while a sweep was running.
func sweepInFlight(g uint64) bool { return g%2 == 1 }

// WipeAll destroys every [Memory] this package has handed out and not
// yet reclaimed, including [Sealer] and [SoftwareProvider] keys, and retries
// the release of every mapping a failed construction could not give back. It
// does not touch [Sealed] values; after a [ModeRootKey] sweep they fail
// to open with [ErrSealerWiped] (see [Sealed.Openable]).
//
// It is for orderly shutdown and must be called only by the code that owns the
// process, never by a library: it destroys enclaves belonging to every
// subsystem. Never call it from inside a borrow.
//
// It never panics and never unmaps under a lock holder. A held enclave is
// waited for until its holder lets go or ctx ends, then skipped and counted.
// ctx bounds only waiting (for another sweep, for borrows, for contended
// locks); everything not held is reclaimed even under a done or nil ctx. One
// sweep runs at a time. Enclaves registered mid-sweep are tried but never
// extend the sweep. Give it a deadline:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
//	defer cancel()
//	if n, err := enclave.WipeAll(ctx); n != 0 || err != nil {
//	    log.Printf("enclave: %d still held at exit, err=%v", n, err)
//	}
//
// It runs in two phases inside the one sweep slot: locked memory first (every
// enclave, an [Allocator]'s included), then every registered backend other
// than the default that implements [Sweeper], snapshotted under the registry's
// read lock, sorted by name, and called after releasing it with ctx unchanged,
// nil included. A backend registered after the snapshot waits for the next
// WipeAll; a failing Sweep does not stop the rest.
//
// The count is how many locked-memory entries are still held at return, read
// from the ledgers under their lock, plus every held count a Sweep returned.
// The error is nil, [ErrSweepInProgress] if the call was never admitted (it
// swept nothing), or a [*SweepError] with what the sweep found, each failed
// Sweep included. A ctx ending during an admitted sweep is not an error. It is
// safe to call repeatedly. See docs/shutdown-sweep/engineering.md.
func WipeAll(ctx context.Context) (int, error) {
	if !admitSweep(ctx) {
		return ledgerCount(), ErrSweepInProgress
	}
	defer func() { <-sweepSlot }()

	// Bump before destroying anything: a sweep in flight must read as odd, so
	// Openable errs toward ErrOpenabilityUnknown rather than nil.
	sweepGen.Add(1)
	// Back to even on every return path.
	defer sweepGen.Add(1)

	if sweepParkedForTest != nil {
		sweepParkedForTest()
	}

	// Armed before the first TryLock, so a holder counted below sees it when it
	// lets go.
	sweepWaiting.Store(true)
	defer sweepWaiting.Store(false)

	// A nil ctx must neither panic nor wait; context.Background's Done is nil
	// too, so the distinction is made here.
	mayWait := ctx != nil
	var done <-chan struct{}
	if mayWait {
		done = ctx.Done()
	}

	// Corruption is tallied per entry in corruptNoted, not read from the
	// ledger (a reclaimed corrupt entry is gone from it) and not per release
	// attempt (a refused release reports it again on retry).
	unwiped := 0

	// owed is the first pass's snapshot. Later registrations are tried on every
	// pass but never waited for and never earn a pass.
	var owed map[*memoryState]struct{}

sweep:
	for pass := 1; ; pass++ {
		// Drain before trying any lock; a wake-up pending after this is fresh.
		select {
		case <-sweepWake:
		default:
		}

		if sweepPassForTest != nil {
			sweepPassForTest(pass)
		}

		// Snapshot and unlock before destroying: settleRelease takes
		// registryMu. Every registered entry is tried on every pass, because a
		// write TryLock loses to any momentary reader. Orphans are never held,
		// so their TryLock always succeeds.
		registryMu.Lock()
		batch := make([]*memoryState, 0, len(live)+len(orphans))
		for e := range live {
			batch = append(batch, e)
		}
		for o := range orphans {
			batch = append(batch, o)
		}
		registryMu.Unlock()

		if owed == nil {
			owed = make(map[*memoryState]struct{}, len(batch))
			for _, e := range batch {
				owed[e] = struct{}{}
			}
		}

		if len(batch) == 0 {
			break
		}

		// progressed: an owed entry's pages went back (earns an immediate pass).
		// held: an owed enclave's holder will wake us. contended: an owed
		// TryLock failed with nobody to wake us (immediate retry, never a wait).
		var progressed, held, contended bool

		for _, e := range batch {
			_, isOwed := owed[e]
			outcome, err := e.tryRelease()
			switch outcome {
			case tryHeld:
				held = held || isOwed
				continue
			case tryContended:
				contended = contended || isOwed
				continue
			case tryReleased:
			}

			if !settleRelease(e, err) {
				continue
			}
			if errors.Is(err, ErrReleasedWithoutWipe) {
				unwiped++
			}
			// Also reached when a racing Destroy won; the entry still left the ledger.
			progressed = progressed || isOwed
		}

		// The only retry not gated on ctx; finite, one per owed entry.
		if progressed {
			continue
		}
		if !held && !contended {
			break
		}

		// Checked before the select so a done ctx never waits even with a
		// wake-up pending, and so contention cannot loop past the deadline.
		if !mayWait || ctx.Err() != nil {
			break
		}
		if contended {
			continue
		}
		if sweepWaitingForTest != nil {
			sweepWaitingForTest()
		}
		select {
		case <-sweepWake:
		case <-done:
			break sweep
		}
	}

	// Phase 2, still inside the sweep slot.
	backendHeld, failures := sweepBackends(ctx)

	// The count is the ledger itself, not a tally, so an enclave registered
	// mid-sweep is never reported as reclaimed. Read after phase 2, which may
	// destroy enclaves a backend holds.
	remaining := ledgerCount() + backendHeld

	registryMu.Lock()
	corrupt := len(corruptNoted)
	clear(corruptNoted)
	registryMu.Unlock()

	if corrupt > 0 || unwiped > 0 || len(failures) > 0 {
		return remaining, &SweepError{Corrupt: corrupt, Unwiped: unwiped, Backends: failures}
	}
	return remaining, nil
}

// sweepBackends is WipeAll's second phase: it calls Sweep, in name order, on
// the registered sweepers snapshotted once, with ctx unchanged (nil included).
// It returns the sum of their held counts, a negative count read as zero, and
// one failure per Sweep that returned an error. A failure does not stop the
// rest; a panic is the backend's own and is not recovered.
func sweepBackends(ctx context.Context) (int, []BackendSweepFailure) {
	held := 0
	var failures []BackendSweepFailure
	for _, s := range registeredSweepers() {
		n, err := s.sweeper.Sweep(ctx)
		if n > 0 {
			held += n
		}
		if err != nil {
			failures = append(failures, BackendSweepFailure{Backend: s.name, Err: err})
		}
	}
	return held, failures
}

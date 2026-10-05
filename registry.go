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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// The registry is a shutdown ledger for a cooperative sweep, not a fault
// handler: it is touched on construction, on destruction and by WipeAll, and
// never on the borrow path. See docs/shutdown-sweep/engineering.md.

// The sweep waits for a held enclave by event, not by sleeping. sweepWaiting
// is armed for a whole sweep; a lock holder reads it after letting go and only
// then calls wakeSweep (see MemoryEnclave.unhold). sweepWake holds at most one
// pending wake-up, so wake-ups coalesce and a sender never blocks. The sweep
// drains it at the start of every pass, before trying any lock, so no release
// is missed; the argument is on MemoryEnclave.holders.
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

var (
	registryMu sync.Mutex
	// live holds every enclave constructed and not yet released.
	live = make(map[*MemoryEnclave]struct{})
	// orphans holds the mappings failed constructions could not give back.
	orphans = make(map[*orphanRecord]struct{})
	// destroyedCorrupt holds enclaves whose Destroy found a failed canary since
	// the last admitted sweep, which reports and clears them.
	destroyedCorrupt = make(map[*MemoryEnclave]struct{})

	// sweepGen is a sequence lock behind [SealedEnclave.Openable]'s fallback:
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

// ErrSweepInProgress is returned by [WipeAll] when it was never admitted:
// another sweep held the process's single sweep slot and this call stopped
// waiting for it, when its ctx ended or at once for a nil ctx. It is not a
// [SweepError] and says nothing about the memory: the call reclaimed nothing,
// and the count returned with it is the current ledger count.
var ErrSweepInProgress = errors.New("enclave: another WipeAll is in progress; nothing was swept")

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

// orphanRecord is a mapping a failed construction could not hand back to the
// kernel, kept so [WipeAll] can retry it. refund returns the construction's
// [Allocator] charge and is nil when there is none to return. It runs exactly
// once: only WipeAll touches a record after adoption, and the record leaves the
// ledger in the same step that runs the refund.
type orphanRecord struct {
	m      *mapping
	refund func()
}

// adoptOrphan puts the mapping a failed construction's err carries onto the
// orphan ledger, with refund to run when a sweep releases it. It is a no-op
// when err left nothing mapped. Public constructors call it after the refund
// decision is made, so a sweep never reaches a record without its refund.
func adoptOrphan(err error, refund func()) {
	var held *pagesHeldError
	if !errors.As(err, &held) || held.orphan == nil {
		return
	}
	o := &orphanRecord{m: held.orphan, refund: refund}
	// One adoption per mapping, however often the error is passed around.
	held.orphan = nil

	registryMu.Lock()
	orphans[o] = struct{}{}
	registryMu.Unlock()
}

// releaseOrphan retries o's release. When the pages went back (by
// releasedPages, the predicate Destroy uses) it runs the refund, drops the
// record and reports true. The caller holds the sweep slot.
func releaseOrphan(o *orphanRecord) (released bool, err error) {
	err = o.m.release()
	if !releasedPages(err) {
		return false, err
	}
	if o.refund != nil {
		o.refund()
	}
	registryMu.Lock()
	delete(orphans, o)
	registryMu.Unlock()
	return true, err
}

// sweepGeneration reports the current sweep sequence. A sealed value records
// it before it seals; an odd value means a sweep was in flight.
func sweepGeneration() uint64 { return sweepGen.Load() }

// sweepInFlight reports whether g was taken while a sweep was running.
func sweepInFlight(g uint64) bool { return g%2 == 1 }

// register adds e to the shutdown ledger and returns it. It publishes e to a
// concurrent [WipeAll], so it must be the last step of construction, after
// every field a sweep reads (release in particular) is set; registryMu is the
// happens-before edge that makes them visible to the sweep.
func register(e *MemoryEnclave) *MemoryEnclave {
	registryMu.Lock()
	live[e] = struct{}{}
	registryMu.Unlock()
	return e
}

// deregister removes e from the shutdown ledger. It is a no-op for an enclave
// that is not on it.
func deregister(e *MemoryEnclave) {
	registryMu.Lock()
	delete(live, e)
	registryMu.Unlock()
}

// noteCorrupted records that Destroy found e's canary broken, so the next
// [WipeAll] reports it even when Destroy's caller discarded the error.
func noteCorrupted(e *MemoryEnclave) {
	registryMu.Lock()
	destroyedCorrupt[e] = struct{}{}
	registryMu.Unlock()
}

// SweepError reports what an admitted [WipeAll] sweep found that is not a held
// page: canary corruption, unwiped unmaps, or both. Neither leaves pages held,
// so the count cannot carry them.
//
// Match it with errors.Is against [ErrEnclaveCorrupted] (Corrupt non-zero) and
// [ErrReleasedWithoutWipe] (Unwiped non-zero); read the numbers with errors.As.
// WipeAll returns one only when a field is non-zero, and never a nil
// *SweepError behind a non-nil error.
type SweepError struct {
	// Corrupt is how many entries this sweep found with a failed canary
	// (enclaves, and orphaned mappings that had material copied in), plus
	// every enclave whose [MemoryEnclave.Destroy] reported [ErrEnclaveCorrupted]
	// since the previous admitted sweep. Each is counted once per sweep. A
	// corrupt entry whose pages the kernel would not release is also in the
	// count WipeAll returns.
	Corrupt int

	// Unwiped is how many entries this sweep unmapped without the in-process
	// overwrite because the mprotect that makes a frozen region writable was
	// denied. Their pages are gone, so they are never in the count.
	Unwiped int
}

// Error implements error. Each non-zero condition is one line naming its
// count and ending in its sentinel's text; both lines appear when both hold.
func (e *SweepError) Error() string {
	var b strings.Builder
	if e.Corrupt > 0 {
		b.WriteString("enclave: ")
		b.WriteString(strconv.Itoa(e.Corrupt))
		b.WriteString(" of the swept enclaves failed canary verification: ")
		b.WriteString(ErrEnclaveCorrupted.Error())
	}
	if e.Unwiped > 0 {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString("enclave: ")
		b.WriteString(strconv.Itoa(e.Unwiped))
		b.WriteString(" of the swept enclaves were unmapped without an in-process wipe because mprotect was denied: ")
		b.WriteString(ErrReleasedWithoutWipe.Error())
	}
	if b.Len() == 0 {
		// Only a hand-built SweepError gets here.
		return "enclave: sweep reported nothing"
	}
	return b.String()
}

// Is reports whether e carries the condition target names:
// [ErrEnclaveCorrupted] when Corrupt is non-zero, [ErrReleasedWithoutWipe]
// when Unwiped is. A zero field never matches its sentinel.
func (e *SweepError) Is(target error) bool {
	switch target {
	case ErrEnclaveCorrupted:
		return e.Corrupt > 0
	case ErrReleasedWithoutWipe:
		return e.Unwiped > 0
	}
	return false
}

// WipeAll destroys every [MemoryEnclave] this package has handed out and not
// yet reclaimed, including [Sealer] and [SoftwareProvider] keys, and retries
// the release of every mapping a failed construction could not give back. It
// does not touch [SealedEnclave] values; after a [ModeRootKey] sweep they fail
// to open with [ErrSealerWiped] (see [SealedEnclave.Openable]).
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
// The count is how many entries are still held at return, read from the
// ledgers under their lock. The error is nil, [ErrSweepInProgress] if the call
// was never admitted (it swept nothing), or a [*SweepError] with what the sweep
// found. A ctx ending during an admitted sweep is not an error. It is safe to
// call repeatedly. See docs/shutdown-sweep/engineering.md.
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

	// Corruption is tallied per entry, not read from the ledger (a reclaimed
	// corrupt entry is gone from it) and not per release attempt (a refused
	// release reports it again on retry). Keyed by any: enclaves and orphans.
	corrupted := make(map[any]struct{})
	unwiped := 0

	// owed is the first pass's snapshot. Later registrations are tried on every
	// pass but never waited for and never earn a pass.
	var owed map[any]struct{}

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

		// Snapshot and unlock before destroying: deregister takes registryMu.
		// Every registered entry is tried on every pass, because a write TryLock
		// loses to any momentary reader.
		registryMu.Lock()
		batch := make([]*MemoryEnclave, 0, len(live))
		for e := range live {
			batch = append(batch, e)
		}
		strays := make([]*orphanRecord, 0, len(orphans))
		for o := range orphans {
			strays = append(strays, o)
		}
		registryMu.Unlock()

		if owed == nil {
			owed = make(map[any]struct{}, len(batch)+len(strays))
			for _, e := range batch {
				owed[e] = struct{}{}
			}
			for _, o := range strays {
				owed[o] = struct{}{}
			}
		}

		if len(batch) == 0 && len(strays) == 0 {
			break
		}

		// progressed: an owed entry's pages went back (earns an immediate pass).
		// held: an owed enclave's holder will wake us. contended: an owed
		// TryLock failed with nobody to wake us (immediate retry, never a wait).
		var progressed, held, contended bool

		for _, e := range batch {
			_, isOwed := owed[e]
			outcome, err := e.tryReleaseMapping()
			switch outcome {
			case tryHeld:
				held = held || isOwed
				continue
			case tryContended:
				contended = contended || isOwed
				continue
			case tryReleased:
			}

			// Same predicate as Destroy: refund only when the pages went back.
			if e.release != nil && releasedPages(err) {
				e.releaseOnce.Do(e.release)
			}

			if errors.Is(err, ErrEnclaveCorrupted) {
				corrupted[e] = struct{}{}
			}

			if !releasedPages(err) {
				continue
			}

			if errors.Is(err, ErrReleasedWithoutWipe) {
				unwiped++
			}

			deregister(e)
			// Also reached when a racing Destroy won; the entry still left the ledger.
			progressed = progressed || isOwed
		}

		// Orphans have no lock: only this sweep touches an adopted record.
		for _, o := range strays {
			released, err := releaseOrphan(o)
			if errors.Is(err, ErrEnclaveCorrupted) {
				corrupted[o] = struct{}{}
			}
			if released && errors.Is(err, ErrReleasedWithoutWipe) {
				unwiped++
			}
			if released {
				_, isOwed := owed[o]
				progressed = progressed || isOwed
			}
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

	// The count is the ledger itself, not a tally, so an enclave registered
	// mid-sweep is never reported as reclaimed.
	registryMu.Lock()
	remaining := len(live) + len(orphans)
	for e := range destroyedCorrupt {
		corrupted[e] = struct{}{}
	}
	clear(destroyedCorrupt)
	registryMu.Unlock()

	if len(corrupted) > 0 || unwiped > 0 {
		return remaining, &SweepError{Corrupt: len(corrupted), Unwiped: unwiped}
	}
	return remaining, nil
}

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
	"testing"
)

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
// the returned func lifts it; t.Cleanup lifts it as well. The mapping keeps its
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
	protectMemory = func([]byte, protection) error {
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

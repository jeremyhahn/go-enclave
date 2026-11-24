// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// retuneRaceSide is one of the two allocators a retune race drives, with the
// bookkeeping its goroutines share.
type retuneRaceSide struct {
	a *budgetAllocator
	// forceEpoch is odd while a ForceLimit lowering of a is in effect: the
	// forcer bumps it before the lowering and again after the restore.
	forceEpoch atomic.Int64
}

// overcommitted reports whether a's budget is exceeded, read as a
// consistent pair under a.mu, and whether the reading may be judged: only
// when no forced lowering overlapped it, since a forced lowering
// legitimately leaves free negative.
func (s *retuneRaceSide) overcommitted() (inUse, limit int64, over, judged bool) {
	before := s.forceEpoch.Load()
	s.a.mu.RLock()
	limit = s.a.limit.Load()
	free := s.a.free.Load()
	s.a.mu.RUnlock()
	after := s.forceEpoch.Load()
	return limit - free, limit, free < 0, before == after && before%2 == 0
}

// retuneRaceCounts are the controls: each must be non-zero, or the race
// exercised less than it claims.
type retuneRaceCounts struct {
	admitted, refused, transfers, lowerings, forced atomic.Int64
}

// TestAllocator_RetuneRace_AdmissionsDestroysAndTransfers races admissions and destroys against SetLimit, ForceLimit and TransferTo.
func TestAllocator_RetuneRace_AdmissionsDestroysAndTransfers(t *testing.T) {
	const (
		startPages = 4
		maxPages   = 8
		admitters  = 6
		admits     = 200
		retunes    = 150
	)
	sides := make([]*retuneRaceSide, 2)
	for i := range sides {
		a, err := newBudgetAllocator(startPages * pageSize)
		if err != nil {
			t.Fatalf("newBudgetAllocator: %v", err)
		}
		sides[i] = &retuneRaceSide{a: a}
	}
	start := sides[0].a.Limit() + sides[1].a.Limit()

	var (
		counts  retuneRaceCounts
		delta   atomic.Int64
		retune  sync.RWMutex
		wg      sync.WaitGroup
		workers = func(n int, f func(g int)) {
			for g := 0; g < n; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					f(g)
				}()
			}
		}
	)

	for _, s := range sides {
		// Admitters: one-page enclaves through New and NewSized, destroyed at once.
		workers(admitters, func(g int) {
			for i := 0; i < admits; i++ {
				var (
					e   *lockedRegion
					err error
				)
				if (g+i)%2 == 0 {
					e, err = s.a.admitData(material())
				} else {
					e, err = s.a.admitSized(int(pageSize / 2))
				}
				if err != nil {
					var be *BudgetError
					if !errors.As(err, &be) || !errors.Is(err, ErrBudgetExhausted) {
						t.Errorf("refused admission err = %v, want a *BudgetError", err)
					}
					counts.refused.Add(1)
					continue
				}
				counts.admitted.Add(1)
				if inUse, limit, over, judged := s.overcommitted(); over && judged {
					t.Errorf("InUse = %d above Limit = %d with no forced lowering", inUse, limit)
				}
				e.Destroy()
			}
		})

		// SetLimit up and down by a page, within [1, maxPages] pages.
		workers(1, func(int) {
			for i := 0; i < retunes; i++ {
				retune.Lock()
				old := s.a.Limit()
				target := old + pageSize
				if i%2 == 1 || target > maxPages*pageSize {
					target = old - pageSize
				}
				if target >= pageSize {
					switch err := s.a.SetLimit(target); {
					case err == nil:
						delta.Add(target - old)
						if target < old {
							counts.lowerings.Add(1)
						}
					case !errors.Is(err, ErrBudgetInUse):
						t.Errorf("SetLimit(%d) err = %v, want nil or ErrBudgetInUse", target, err)
					}
				}
				retune.Unlock()
				runtime.Gosched()
			}
		})

		// ForceLimit lowers beneath live enclaves, then restores its own limit.
		workers(1, func(int) {
			for i := 0; i < retunes; i++ {
				retune.Lock()
				old := s.a.Limit()
				s.forceEpoch.Add(1)
				if _, err := s.a.ForceLimit(old / 2); err != nil {
					t.Errorf("ForceLimit(%d) lowering err = %v", old/2, err)
				}
				counts.forced.Add(1)
				runtime.Gosched()
				if _, err := s.a.ForceLimit(old); err != nil {
					t.Errorf("ForceLimit(%d) restore err = %v", old, err)
				}
				s.forceEpoch.Add(1)
				retune.Unlock()
				runtime.Gosched()
			}
		})
	}

	// Transfers in both directions, racing each other under the read side.
	for i := range sides {
		src, dst := sides[i].a, sides[1-i].a
		workers(2, func(int) {
			for j := 0; j < retunes; j++ {
				retune.RLock()
				switch err := src.TransferTo(dst, pageSize); {
				case err == nil:
					counts.transfers.Add(1)
				case !errors.Is(err, ErrBudgetInUse):
					t.Errorf("TransferTo err = %v, want nil or ErrBudgetInUse", err)
				}
				retune.RUnlock()
				runtime.Gosched()
			}
		})
	}

	waitBounded(t, &wg, 60*time.Second, "retune race")

	// The race's own invariants: every destroy refunded its charge exactly,
	// and only SetLimit changed the sum of the limits.
	for i, s := range sides {
		if u := s.a.InUse(); u != 0 {
			t.Errorf("allocator %d: InUse = %d after every destroy, want 0", i, u)
		}
		if av, l := s.a.Available(), s.a.Limit(); av != l {
			t.Errorf("allocator %d: Available = %d, want the whole Limit %d", i, av, l)
		}
	}
	if got, want := sides[0].a.Limit()+sides[1].a.Limit(), start+delta.Load(); got != want {
		t.Errorf("Limit sum = %d, want start %d + SetLimit deltas %d = %d", got, start, delta.Load(), want)
	}

	// Every racing attempt may legitimately be refused, so a correct
	// allocator need not admit, refuse, lower or transfer during the race,
	// and the race may leave a side at limit 0. A quiet phase does each
	// once from budgets set here, so it depends on nothing the race did.
	quietLimit := 2 * pageSize
	for i, s := range sides {
		if err := s.a.SetLimit(quietLimit); err != nil {
			t.Fatalf("allocator %d: SetLimit(%d) before the quiet phase err = %v", i, quietLimit, err)
		}
	}
	for _, s := range sides {
		forceRetuneRaceRefusal(t, s.a, &counts)
	}
	forceRetuneRaceTransfers(t, sides[0].a, sides[1].a, &counts)

	for name, n := range map[string]int64{
		"admission": counts.admitted.Load(), "refusal": counts.refused.Load(),
		"transfer": counts.transfers.Load(), "SetLimit lowering": counts.lowerings.Load(),
		"ForceLimit lowering": counts.forced.Load(),
	} {
		if n == 0 {
			t.Errorf("no %s happened; the race did not exercise it", name)
		}
	}
	for i, s := range sides {
		if u, l := s.a.InUse(), s.a.Limit(); u != 0 || l != quietLimit {
			t.Errorf("allocator %d after the quiet phase: InUse = %d, Limit = %d, want 0 and %d", i, u, l, quietLimit)
		}
	}
}

// forceRetuneRaceRefusal raises a's limit by a page, lowers it to one page
// (a SetLimit lowering that cannot be refused), fills it with a
// one-page enclave, checks that a second admission is refused with a
// *BudgetError, and restores the limit. a must have no live enclaves.
func forceRetuneRaceRefusal(t *testing.T, a *budgetAllocator, counts *retuneRaceCounts) {
	t.Helper()
	old := a.Limit()
	// Raise by a page first, so the lowering to one page always lowers.
	if err := a.SetLimit(old + pageSize); err != nil {
		t.Fatalf("SetLimit(%d) raise err = %v", old+pageSize, err)
	}
	if err := a.SetLimit(pageSize); err != nil {
		t.Fatalf("SetLimit(%d) err = %v", pageSize, err)
	}
	counts.lowerings.Add(1)
	defer func() {
		if err := a.SetLimit(old); err != nil {
			t.Errorf("SetLimit(%d) restore err = %v", old, err)
		}
	}()
	held, err := a.admitSized(int(pageSize / 2))
	if err != nil {
		t.Fatalf("admitSized into an empty one-page budget err = %v", err)
	}
	counts.admitted.Add(1)
	defer held.Destroy()
	e, err := a.admitData(material())
	if err == nil {
		e.Destroy()
		t.Fatalf("admission beyond a full one-page budget succeeded, want ErrBudgetExhausted")
	}
	var be *BudgetError
	if !errors.As(err, &be) || !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("refused admission err = %v, want a *BudgetError", err)
	}
	counts.refused.Add(1)
}

// forceRetuneRaceTransfers moves one page from a to b and back. Both must have
// no live enclaves and a limit of at least one page, so neither is refused.
func forceRetuneRaceTransfers(t *testing.T, a, b *budgetAllocator, counts *retuneRaceCounts) {
	t.Helper()
	for _, p := range [][2]*budgetAllocator{{a, b}, {b, a}} {
		if err := p[0].TransferTo(p[1], pageSize); err != nil {
			t.Fatalf("TransferTo(%d) with an empty budget err = %v", pageSize, err)
		}
		counts.transfers.Add(1)
	}
}

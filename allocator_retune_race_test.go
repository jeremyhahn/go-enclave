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

// TestAllocator_RetuneRace_AdmissionsDestroysAndTransfers races New, NewSized
// and Destroy on two allocators against SetLimit up and down, ForceLimit
// lowerings and TransferTo in both directions.
//
// In-run check: after each admission the admitter reads limit and free under
// a.mu.RLock (a consistent pair, never a lock-free false alarm) and requires
// InUse <= Limit, judged only when no ForceLimit lowering overlapped the
// reading (forceEpoch even and unchanged), because a forced lowering
// legitimately drives free negative beneath live enclaves.
//
// End-state check: SetLimit and ForceLimit run under the write side of a
// test-only RWMutex and transfers under its read side, so a SetLimit or
// ForceLimit sees a stable limit and its delta is exact, while transfers race
// each other and every retune races admissions and destroys. Each forcer
// restores its own lowering before releasing that lock. At the end the sum of
// the limits is the start plus the SetLimit deltas: transfers conserve it.
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

	// The race may or may not refuse an admission; force one on each side so
	// the refusal path is always exercised, and leave the limit as it was.
	for _, s := range sides {
		forceRetuneRaceRefusal(t, s.a, &counts)
	}

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
}

// forceRetuneRaceRefusal lowers a's limit to one page, fills it with a
// one-page enclave, checks that a second admission is refused with a
// *BudgetError, and restores the limit. a must have no live enclaves.
func forceRetuneRaceRefusal(t *testing.T, a *budgetAllocator, counts *retuneRaceCounts) {
	t.Helper()
	old := a.Limit()
	if err := a.SetLimit(pageSize); err != nil {
		t.Fatalf("SetLimit(%d) err = %v", pageSize, err)
	}
	defer func() {
		if err := a.SetLimit(old); err != nil {
			t.Errorf("SetLimit(%d) restore err = %v", old, err)
		}
	}()
	held, err := a.admitSized(int(pageSize / 2))
	if err != nil {
		t.Fatalf("admitSized into an empty one-page budget err = %v", err)
	}
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

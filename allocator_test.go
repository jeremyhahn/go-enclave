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
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// FuzzAllocatorAdmission drives an Allocator with a small budget through a
// sequence of allocations and destroys decoded from the input, on one
// goroutine (concurrency stays with the race tests). The first byte sets the
// budget, 1 to 8 pages; each later pair is one operation: an even first byte
// allocates ((op>>1)<<8 | arg) bytes, an odd one destroys live[arg%len(live)].
// Properties: InUse matches the page-rounded bytes of the live handles and
// never exceeds the budget; a request over the remaining budget is refused
// with a *BudgetError matching ErrBudgetExhausted; destroying every handle
// returns InUse to zero.
func FuzzAllocatorAdmission(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{3, 0, 1, 0x10, 0, 0, 0xff, 1, 0, 0x20, 0})
	f.Add([]byte{7, 0x7e, 0xff, 0, 1, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		const maxOps = 64
		budget := int64(1+data[0]%8) * pageSize
		a, err := newBudgetAllocator(budget)
		if err != nil {
			t.Fatalf("newBudgetAllocator(%d): %v", budget, err)
		}

		type handle struct {
			m      *Memory
			charge int64
		}
		var live []handle
		var used int64
		destroy := func(i int) {
			h := live[i]
			live = append(live[:i], live[i+1:]...)
			if err := h.m.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			used -= h.charge
		}
		defer func() {
			for len(live) > 0 {
				destroy(len(live) - 1)
			}
		}()

		ops := data[1:]
		for i := 0; i+1 < len(ops) && i < 2*maxOps; i += 2 {
			op, arg := ops[i], ops[i+1]
			if op&1 == 1 {
				if len(live) > 0 {
					destroy(int(arg) % len(live))
				}
			} else {
				n := int(op>>1)<<8 | int(arg)
				charge := LockedSize(n)
				m, err := a.admitSized(n)
				switch {
				case n == 0:
					if !errors.Is(err, ErrInvalidSize) {
						t.Fatalf("NewSized(0) = %v, want ErrInvalidSize", err)
					}
				case charge > budget-used:
					var be *BudgetError
					if !errors.Is(err, ErrBudgetExhausted) || !errors.As(err, &be) {
						t.Fatalf("NewSized(%d) with %d of %d bytes used = %v, want a *BudgetError", n, used, budget, err)
					}
					if be.Requested != charge || be.InUse != used || be.Limit != budget {
						t.Fatalf("BudgetError = %+v, want Requested %d, InUse %d, Limit %d", *be, charge, used, budget)
					}
				case err != nil:
					t.Fatalf("NewSized(%d) with %d of %d bytes used: %v", n, used, budget, err)
				default:
					live = append(live, handle{m, charge})
					used += charge
				}
				if err != nil && m != nil {
					t.Fatalf("NewSized(%d) returned an enclave with error %v", n, err)
				}
			}
			if got := a.InUse(); got != used || got > a.Limit() {
				t.Fatalf("InUse = %d, want %d within the limit %d", got, used, a.Limit())
			}
		}

		for len(live) > 0 {
			destroy(0)
		}
		if got := a.InUse(); got != 0 {
			t.Fatalf("InUse after destroying every handle = %d, want 0", got)
		}
	})
}

func TestNewAllocator_InvalidBudget(t *testing.T) {
	for _, n := range []int64{0, -1, -4096} {
		a, err := newBudgetAllocator(n)
		if !errors.Is(err, ErrInvalidBudget) {
			t.Errorf("newBudgetAllocator(%d) err = %v, want ErrInvalidBudget", n, err)
		}
		if a != nil {
			t.Errorf("newBudgetAllocator(%d) returned a non-nil allocator on error", n)
		}
	}
	a, err := newBudgetAllocator(4096)
	if err != nil {
		t.Fatalf("newBudgetAllocator(4096): %v", err)
	}
	if a.Limit() != 4096 {
		t.Errorf("Limit = %d, want 4096", a.Limit())
	}
	if a.InUse() != 0 || a.Available() != 4096 {
		t.Errorf("fresh allocator InUse=%d Available=%d, want 0 and 4096", a.InUse(), a.Available())
	}
}

// TestNewAllocatorWithinRLimit_InvalidBudget pins that a non-positive budget
// is ErrInvalidBudget, never a host-configuration error.
func TestNewAllocatorWithinRLimit_InvalidBudget(t *testing.T) {
	for _, n := range []int64{0, -1, -4096, math.MinInt64} {
		a, err := newBudgetAllocatorWithinRLimit(n)
		if !errors.Is(err, ErrInvalidBudget) {
			t.Errorf("newBudgetAllocatorWithinRLimit(%d) err = %v, want ErrInvalidBudget", n, err)
		}
		if errors.Is(err, ErrBudgetExceedsRLimit) {
			t.Errorf("newBudgetAllocatorWithinRLimit(%d) reported a bad budget as an rlimit refusal", n)
		}
		if a != nil {
			t.Errorf("newBudgetAllocatorWithinRLimit(%d) returned a non-nil allocator on error", n)
		}
	}
}

// TestNewAllocatorWithinRLimit_AcceptsModestBudget is the control for the
// refusal tests: a single page passes on any host that can run this suite, and
// the allocator returned is usable.
func TestNewAllocatorWithinRLimit_AcceptsModestBudget(t *testing.T) {
	a, err := newBudgetAllocatorWithinRLimit(pageSize)
	if err != nil {
		t.Fatalf("newBudgetAllocatorWithinRLimit(%d): %v", pageSize, err)
	}
	if a.Limit() != pageSize {
		t.Errorf("Limit = %d, want %d — the budget must be the one asked for, not a clamped figure", a.Limit(), pageSize)
	}

	material := []byte("checked-allocator-material")
	e, err := a.admitData(material)
	if err != nil {
		t.Fatalf("New through a checked allocator: %v", err)
	}
	defer e.Destroy()
	if !holds(e, []byte("checked-allocator-material")) {
		t.Error("material did not survive into an enclave from a checked allocator")
	}
	if a.InUse() != pageSize {
		t.Errorf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
}

func TestAllocator_New_Admits(t *testing.T) {
	limit := 4 * pageSize
	a, err := newBudgetAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	material := []byte("admitted-key-material")

	e, err := a.admitData(material)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Destroy()

	// Charged a whole page: the budget is in what the kernel locks.
	if a.InUse() != pageSize {
		t.Errorf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
	if a.Available() != limit-pageSize {
		t.Errorf("Available = %d, want %d", a.Available(), limit-pageSize)
	}
	if ok, err := e.EqualTo([]byte("admitted-key-material")); err != nil || !ok {
		t.Errorf("EqualTo = %v, %v; want the material held intact", ok, err)
	}
}

// TestAllocator_New_RefusesOverBudget pins that an over-budget allocation is
// refused with ErrBudgetExhausted, returns no enclave, and leaves the budget
// unchanged.
func TestAllocator_New_RefusesOverBudget(t *testing.T) {
	// One page of budget holds exactly one enclave, however small its material.
	a, err := newBudgetAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	first, err := a.admitData(bytes.Repeat([]byte("x"), 24))
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	defer first.Destroy()

	before := a.InUse()
	e, err := a.admitData(bytes.Repeat([]byte("y"), 16))
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("over-budget New err = %v, want ErrBudgetExhausted", err)
	}
	if e != nil {
		t.Error("over-budget New returned a non-nil enclave")
	}
	if a.InUse() != before {
		t.Errorf("InUse = %d after refusal, want unchanged %d", a.InUse(), before)
	}

	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("err is not a *BudgetError: %v", err)
	}
	// The figures are in locked bytes throughout: 16 bytes of material costs
	// a page, and the page already taken is what leaves no room.
	if be.Requested != pageSize || be.Limit != pageSize || be.InUse != pageSize {
		t.Errorf("BudgetError = %+v, want Requested=InUse=Limit=%d", be, pageSize)
	}
}

// TestAllocator_New_WipesSourceOnRefusal pins that a refused allocation still
// wipes the caller's slice.
func TestAllocator_New_WipesSourceOnRefusal(t *testing.T) {
	a, err := newBudgetAllocator(8)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	src := []byte("this-will-be-refused")
	if _, err := a.New(src); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("New err = %v, want ErrBudgetExhausted", err)
	}
	for i, b := range src {
		if b != 0 {
			t.Fatalf("src[%d] = %#x after refusal, want the slice wiped", i, b)
		}
	}
}

// TestAllocator_Destroy_ReleasesReservation pins that Destroy returns the
// reservation: a full budget refuses, and after Destroy an identical allocation
// is admitted. The enclave reads back the same either way, so the property is
// asserted on the allocator.
func TestAllocator_Destroy_ReleasesReservation(t *testing.T) {
	a, err := newBudgetAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := a.admitData(bytes.Repeat([]byte("a"), 16))
	if err != nil {
		t.Fatalf("New (full): %v", err)
	}
	if a.InUse() != pageSize {
		t.Fatalf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}

	// Budget is full: another allocation must be refused.
	if _, err := a.New([]byte("b")); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("New while full err = %v, want ErrBudgetExhausted", err)
	}

	e.Destroy()
	if a.InUse() != 0 {
		t.Fatalf("InUse = %d after Destroy, want 0 (reservation not released)", a.InUse())
	}

	// The freed budget must now admit an identical allocation.
	e2, err := a.admitData(bytes.Repeat([]byte("c"), 16))
	if err != nil {
		t.Fatalf("New after release: %v (budget was not returned)", err)
	}
	e2.Destroy()
}

// TestAllocator_Destroy_ReleasesExactlyOnce guards against a double release
// underflowing the counter: a second (idempotent) Destroy must not return the
// reservation twice and drive InUse negative, which would let the allocator
// admit more than its budget.
func TestAllocator_Destroy_ReleasesExactlyOnce(t *testing.T) {
	limit := 2 * pageSize
	a, err := newBudgetAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.admitData(bytes.Repeat([]byte("z"), 32))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	e.Destroy()
	e.Destroy() // idempotent; must not release twice
	if a.InUse() != 0 {
		t.Fatalf("InUse = %d after double Destroy, want exactly 0", a.InUse())
	}
	if a.Available() != limit {
		t.Fatalf("Available = %d after double Destroy, want the full %d", a.Available(), limit)
	}
}

func TestAllocator_New_Empty(t *testing.T) {
	a, err := newBudgetAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	for name, in := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			e, err := a.admitData(in)
			if !errors.Is(err, ErrEmptyEnclave) {
				t.Errorf("New(%s) err = %v, want ErrEmptyEnclave", name, err)
			}
			if e != nil {
				t.Errorf("New(%s) returned a non-nil enclave", name)
			}
			if a.InUse() != 0 {
				t.Errorf("InUse = %d after empty New, want 0 (no reservation)", a.InUse())
			}
		})
	}
}

// TestAllocator_Concurrent runs many concurrent New/Destroy cycles against a
// tight budget. The invariant under -race: InUse never exceeds the limit at
// any observed point (the CAS refuses rather than overshooting), and the
// counter returns to exactly zero once every enclave is destroyed.
func TestAllocator_Concurrent(t *testing.T) {
	// Budget in pages: each enclave costs one whatever its size. The admitted
	// counter guards against a budget that silently admits nothing.
	const capacity = 5
	limit := capacity * pageSize
	a, err := newBudgetAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var admitted atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				e, err := a.admitData(bytes.Repeat([]byte("k"), 40))
				if err != nil {
					if !errors.Is(err, ErrBudgetExhausted) {
						t.Errorf("unexpected New err: %v", err)
					}
					continue
				}
				admitted.Add(1)
				if u := a.InUse(); u > limit {
					t.Errorf("InUse = %d exceeded limit %d", u, limit)
				}
				e.Destroy()
			}
		}()
	}
	wg.Wait()

	if admitted.Load() == 0 {
		t.Fatal("every allocation was refused; the budget admits nothing and this test asserted nothing")
	}
	if a.InUse() != 0 {
		t.Errorf("InUse = %d after all destroys, want 0", a.InUse())
	}
	if a.Available() != limit {
		t.Errorf("Available = %d, want the full %d", a.Available(), limit)
	}
}

// TestAllocator_New_KeepsTheChargeForPagesACleanupCouldNotRelease pins that
// when a refused freeze's cleanup is also refused and the pages stay locked, New
// keeps the charge. The control arm lets the unmap succeed and expects a full
// refund.
func TestAllocator_New_KeepsTheChargeForPagesACleanupCouldNotRelease(t *testing.T) {
	for _, tc := range []struct {
		name       string
		bypassOK   bool
		wantInUse  int64
		wantHeldOK bool
	}{
		{"the bypass returned the pages", true, 0, false},
		{"nothing could return the pages", false, pageSize, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := newBudgetAllocator(4 * pageSize)
			if err != nil {
				t.Fatalf("NewAllocator: %v", err)
			}

			denied := errors.New("mprotect denied by policy")
			// Stranded pages are on the orphan ledger; reclaim them with a sweep, as
			// production does, never behind the ledger's back. Registered first, it
			// runs after the seams are restored.
			t.Cleanup(func() { _, _ = WipeAll(context.Background()) })
			prevProtect, prevUnmap := protectMemory, unmapMemory
			swapSeam(t, &protectMemory, func(b []byte, p protection) error {
				if p == protNoAccess {
					return prevProtect(b, p) // guard pages at construction
				}
				return denied
			})
			swapSeam(t, &unmapMemory, func(b []byte) error {
				if tc.bypassOK {
					return prevUnmap(b)
				}
				return errors.New("munmap denied too")
			})

			e, err := a.admitData(material())
			if err == nil {
				e.Destroy()
				t.Fatal("Allocator.New succeeded although its freeze was refused")
			}
			if !errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Errorf("Allocator.New = %v, want ErrLockedMemoryUnavailable", err)
			}
			if got := pagesHeld(err); got != tc.wantHeldOK {
				t.Errorf("pagesHeld(%v) = %v, want %v", err, got, tc.wantHeldOK)
			}
			if used := a.InUse(); used != tc.wantInUse {
				t.Errorf("InUse = %d after the failed construction, want %d", used, tc.wantInUse)
			}
		})
	}
}

// TestAllocator_New_RefundsWhenTheCleanupUnlockedButCouldNotUnmap pins that a
// failed construction whose cleanup unlocked the pages but was refused the
// munmap is refunded at once: the pages cost address space, not locked memory.
func TestAllocator_New_RefundsWhenTheCleanupUnlockedButCouldNotUnmap(t *testing.T) {
	a, err := newBudgetAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var stranded bool
	// Reclaimed through the orphan ledger, never freed behind its back; see
	// TestAllocator_New_KeepsTheChargeForPagesACleanupCouldNotRelease. Registered
	// first, it runs after the seams are restored.
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })
	// Only the freeze (read-only) is refused, so construction fails and the
	// cleanup wipes, unlocks, and is refused the unmap.
	prevProtect := protectMemory
	swapSeam(t, &protectMemory, func(b []byte, p protection) error {
		if p == protReadOnly {
			return errors.New("mprotect denied by policy")
		}
		return prevProtect(b, p)
	})
	swapSeam(t, &unmapMemory, func([]byte) error {
		stranded = true
		return errors.New("munmap: cannot allocate memory")
	})

	e, err := a.admitData(material())
	if err == nil {
		e.Destroy()
		t.Fatal("Allocator.New succeeded although its freeze was refused")
	}
	if !stranded {
		t.Fatal("the cleanup never reached the munmap; this test would be vacuous")
	}
	if !pagesHeld(err) {
		t.Errorf("pagesHeld(%v) = false, want true: the pages are still mapped", err)
	}
	if lockedPagesHeld(err) {
		t.Errorf("lockedPagesHeld(%v) = true, want false: the munlock succeeded", err)
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after a failed construction left nothing locked, want 0", used)
	}
}

// TestAllocator_NewSized_RefundsWhenALockFailureLeavesNothingLocked pins that
// an mlock refused at the ceiling, with the rollback's munmap succeeding, refunds
// the charge and is not marked as holding pages.
func TestAllocator_NewSized_RefundsWhenALockFailureLeavesNothingLocked(t *testing.T) {
	a, err := newBudgetAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	swapSeam(t, &lockMemory, func([]byte) error { return errors.New("mlock: cannot allocate memory") })
	unmaps := 0
	prevUnmap := unmapMemory
	swapSeam(t, &unmapMemory, func(b []byte) error {
		unmaps++
		return prevUnmap(b)
	})

	_, err = a.NewSized(32)
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("NewSized = %v, want ErrLockedMemoryUnavailable", err)
	}
	if unmaps != 1 {
		t.Errorf("the rollback unmapped %d times, want 1: the mapping it gave up was not returned", unmaps)
	}
	if pagesHeld(err) {
		t.Errorf("pagesHeld(%v) = true, want false: the rollback unmapped the region", err)
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after a construction that left nothing locked, want 0", used)
	}
}

// material returns a non-empty slice; every enclave costs one page regardless.
func material() []byte { return bytes.Repeat([]byte("k"), 40) }

// waitBounded joins wg or fails the test, so a deadlock regression is a named
// failure rather than a suite timeout.
func waitBounded(t *testing.T, wg *sync.WaitGroup, d time.Duration, what string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not finish within %s (deadlock)", what, d)
	}
}

// TestAllocator_SetLimit_RaiseAdmitsWhatWasRefused pins that a runtime raise
// admits an allocation refused just before it.
func TestAllocator_SetLimit_RaiseAdmitsWhatWasRefused(t *testing.T) {
	a, err := newBudgetAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	first, err := a.admitData(material())
	if err != nil {
		t.Fatalf("New (filling the budget): %v", err)
	}
	defer first.Destroy()

	if _, err := a.NewSized(32); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("NewSized before the raise = %v, want ErrBudgetExhausted", err)
	}

	if err := a.SetLimit(2 * pageSize); err != nil {
		t.Fatalf("SetLimit(raise): %v", err)
	}
	if got := a.Limit(); got != 2*pageSize {
		t.Errorf("Limit = %d after raise, want %d", got, 2*pageSize)
	}
	if got := a.InUse(); got != pageSize {
		t.Errorf("InUse = %d after raise, want the unchanged %d", got, pageSize)
	}
	if got := a.Available(); got != pageSize {
		t.Errorf("Available = %d after raise, want %d", got, pageSize)
	}

	second, err := a.admitSized(32)
	if err != nil {
		t.Fatalf("NewSized after the raise: %v (the new headroom was not admissible)", err)
	}
	second.Destroy()
}

// TestAllocator_SetLimit_RefusesBelowInUse pins that lowering below live
// reservations is refused and changes nothing, while lowering to exactly InUse
// succeeds.
func TestAllocator_SetLimit_RefusesBelowInUse(t *testing.T) {
	a, err := newBudgetAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.admitData([]byte("retune-material"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Destroy()

	err = a.SetLimit(pageSize / 2)
	if !errors.Is(err, ErrBudgetInUse) {
		t.Fatalf("SetLimit below in-use = %v, want ErrBudgetInUse", err)
	}
	var le *BudgetInUseError
	if !errors.As(err, &le) {
		t.Fatalf("err is not a *BudgetInUseError: %v", err)
	}
	if le.Requested != pageSize/2 || le.InUse != pageSize || le.Limit != 4*pageSize {
		t.Errorf("BudgetInUseError = %+v, want Requested=%d InUse=%d Limit=%d",
			le, pageSize/2, pageSize, 4*pageSize)
	}

	// Nothing moved: budget, usage and headroom are exactly as they were.
	if a.Limit() != 4*pageSize || a.InUse() != pageSize || a.Available() != 3*pageSize {
		t.Errorf("after refusal Limit=%d InUse=%d Available=%d, want %d, %d, %d",
			a.Limit(), a.InUse(), a.Available(), 4*pageSize, pageSize, 3*pageSize)
	}
	// And the enclave was not silently invalidated by a budget decision.
	if ok, err := e.EqualTo([]byte("retune-material")); err != nil || !ok {
		t.Errorf("EqualTo after refused lowering = %v, %v; want the material intact", ok, err)
	}

	// CONTROL: lowering to exactly what is in use is legal and must succeed.
	if err := a.SetLimit(pageSize); err != nil {
		t.Fatalf("SetLimit to exactly InUse: %v (a legal lowering was refused)", err)
	}
	if a.Limit() != pageSize || a.InUse() != pageSize || a.Available() != 0 {
		t.Errorf("after legal lowering Limit=%d InUse=%d Available=%d, want %d, %d, 0",
			a.Limit(), a.InUse(), a.Available(), pageSize, pageSize)
	}
	if _, err := a.NewSized(32); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("NewSized after lowering to InUse = %v, want ErrBudgetExhausted", err)
	}
}

func TestAllocator_SetLimit_Bounds(t *testing.T) {
	t.Run("negative is refused and changes nothing", func(t *testing.T) {
		a, err := newBudgetAllocator(2 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		for _, n := range []int64{-1, -pageSize} {
			if err := a.SetLimit(n); !errors.Is(err, ErrInvalidBudget) {
				t.Errorf("SetLimit(%d) = %v, want ErrInvalidBudget", n, err)
			}
		}
		if a.Limit() != 2*pageSize || a.Available() != 2*pageSize {
			t.Errorf("Limit=%d Available=%d after refused negatives, want both %d",
				a.Limit(), a.Available(), 2*pageSize)
		}
	})

	t.Run("zero quiesces, and the allocator comes back", func(t *testing.T) {
		// Zero is a mistake at construction and a deliberate act at runtime;
		// the two constructors differ on it for that reason.
		if _, err := newBudgetAllocator(0); !errors.Is(err, ErrInvalidBudget) {
			t.Fatalf("newBudgetAllocator(0) = %v, want ErrInvalidBudget", err)
		}
		a, err := newBudgetAllocator(pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		if err := a.SetLimit(0); err != nil {
			t.Fatalf("SetLimit(0) on an idle allocator: %v", err)
		}
		if a.Limit() != 0 || a.Available() != 0 || a.InUse() != 0 {
			t.Errorf("quiesced Limit=%d Available=%d InUse=%d, want 0, 0, 0",
				a.Limit(), a.Available(), a.InUse())
		}
		if _, err := a.NewSized(32); !errors.Is(err, ErrBudgetExhausted) {
			t.Errorf("NewSized while quiesced = %v, want ErrBudgetExhausted", err)
		}

		// CONTROL: quiescing is reversible, not a one-way trip.
		if err := a.SetLimit(pageSize); err != nil {
			t.Fatalf("SetLimit(unquiesce): %v", err)
		}
		e, err := a.admitSized(32)
		if err != nil {
			t.Fatalf("NewSized after unquiescing: %v", err)
		}
		e.Destroy()
	})

	t.Run("setting the same budget is a no-op", func(t *testing.T) {
		a, err := newBudgetAllocator(2 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		e, err := a.admitData(material())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer e.Destroy()
		if err := a.SetLimit(2 * pageSize); err != nil {
			t.Fatalf("SetLimit(same): %v", err)
		}
		if a.Limit() != 2*pageSize || a.InUse() != pageSize || a.Available() != pageSize {
			t.Errorf("after no-op Limit=%d InUse=%d Available=%d, want %d, %d, %d",
				a.Limit(), a.InUse(), a.Available(), 2*pageSize, pageSize, pageSize)
		}
	})
}

// TestAllocator_ForceLimit_LowersBeneathLiveReservations pins that ForceLimit
// records a budget below live reservations, reports the excess, keeps the
// enclaves intact, and admits nothing until they drain.
func TestAllocator_ForceLimit_LowersBeneathLiveReservations(t *testing.T) {
	a, err := newBudgetAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e1, err := a.admitData([]byte("first-secret"))
	if err != nil {
		t.Fatalf("New(e1): %v", err)
	}
	e2, err := a.admitData([]byte("second-secret"))
	if err != nil {
		t.Fatalf("New(e2): %v", err)
	}

	excess, err := a.ForceLimit(pageSize)
	if err != nil {
		t.Fatalf("ForceLimit: %v", err)
	}
	// Two pages reserved against a one-page budget: the caller is told by how
	// much, at the moment the change landed.
	if excess != pageSize {
		t.Errorf("excess = %d, want %d", excess, pageSize)
	}
	if a.Limit() != pageSize {
		t.Errorf("Limit = %d, want the forced %d", a.Limit(), pageSize)
	}
	if a.InUse() != 2*pageSize {
		t.Errorf("InUse = %d, want the unchanged %d", a.InUse(), 2*pageSize)
	}
	if a.InUse() <= a.Limit() {
		t.Error("InUse did not exceed Limit; the allocator is not over-subscribed and this test asserted nothing")
	}
	if a.Available() != 0 {
		t.Errorf("Available = %d while over-subscribed, want 0", a.Available())
	}

	// Nothing further is admitted, and the refusal reports the over-subscription
	// rather than hiding it.
	_, err = a.NewSized(32)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("NewSized while over-subscribed = %v, want ErrBudgetExhausted", err)
	}
	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("err is not a *BudgetError: %v", err)
	}
	if be.InUse != 2*pageSize || be.Limit != pageSize {
		t.Errorf("BudgetError = %+v, want InUse=%d Limit=%d", be, 2*pageSize, pageSize)
	}

	// The live enclaves were not invalidated to make the budget fit.
	if ok, err := e1.EqualTo([]byte("first-secret")); err != nil || !ok {
		t.Errorf("e1.EqualTo = %v, %v; want the material intact", ok, err)
	}
	if ok, err := e2.EqualTo([]byte("second-secret")); err != nil || !ok {
		t.Errorf("e2.EqualTo = %v, %v; want the material intact", ok, err)
	}

	// Draining: one Destroy is not enough, because one page of reservations
	// still fills the whole new budget.
	e1.Destroy()
	if a.InUse() != pageSize || a.Available() != 0 {
		t.Errorf("after one Destroy InUse=%d Available=%d, want %d and 0", a.InUse(), a.Available(), pageSize)
	}
	if _, err := a.NewSized(32); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("NewSized after one Destroy = %v, want ErrBudgetExhausted", err)
	}

	e2.Destroy()
	if a.InUse() != 0 || a.Available() != pageSize {
		t.Errorf("after full drain InUse=%d Available=%d, want 0 and %d", a.InUse(), a.Available(), pageSize)
	}
	// CONTROL: once drained the allocator admits again, so the over-subscription
	// was a transient state and not a permanently poisoned budget.
	e3, err := a.admitSized(32)
	if err != nil {
		t.Fatalf("NewSized after the drain: %v", err)
	}
	e3.Destroy()
}

func TestAllocator_ForceLimit_Bounds(t *testing.T) {
	t.Run("a lowering that fits reports no excess", func(t *testing.T) {
		a, err := newBudgetAllocator(4 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		e, err := a.admitData(material())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer e.Destroy()
		excess, err := a.ForceLimit(2 * pageSize)
		if err != nil || excess != 0 {
			t.Fatalf("ForceLimit(fits) = %d, %v; want 0, nil", excess, err)
		}
		if a.Limit() != 2*pageSize || a.InUse() != pageSize || a.Available() != pageSize {
			t.Errorf("Limit=%d InUse=%d Available=%d, want %d, %d, %d",
				a.Limit(), a.InUse(), a.Available(), 2*pageSize, pageSize, pageSize)
		}
	})

	t.Run("raising reports no excess and admits", func(t *testing.T) {
		a, err := newBudgetAllocator(pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		e, err := a.admitData(material())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer e.Destroy()
		if _, err := a.NewSized(32); !errors.Is(err, ErrBudgetExhausted) {
			t.Fatalf("NewSized before the raise = %v, want ErrBudgetExhausted", err)
		}
		excess, err := a.ForceLimit(2 * pageSize)
		if err != nil || excess != 0 {
			t.Fatalf("ForceLimit(raise) = %d, %v; want 0, nil", excess, err)
		}
		second, err := a.admitSized(32)
		if err != nil {
			t.Fatalf("NewSized after ForceLimit raise: %v", err)
		}
		second.Destroy()
	})

	t.Run("the same budget reports the standing excess", func(t *testing.T) {
		a, err := newBudgetAllocator(2 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		e, err := a.admitData(material())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer e.Destroy()
		// Already over-subscribed by one page; re-asserting the same budget must
		// report it rather than silently returning zero.
		if _, err := a.ForceLimit(pageSize / 2); err != nil {
			t.Fatalf("ForceLimit: %v", err)
		}
		excess, err := a.ForceLimit(pageSize / 2)
		if err != nil {
			t.Fatalf("ForceLimit(same): %v", err)
		}
		if want := pageSize - pageSize/2; excess != want {
			t.Errorf("excess = %d, want %d", excess, want)
		}
	})

	t.Run("negative is refused and changes nothing", func(t *testing.T) {
		a, err := newBudgetAllocator(2 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		excess, err := a.ForceLimit(-1)
		if !errors.Is(err, ErrInvalidBudget) || excess != 0 {
			t.Errorf("ForceLimit(-1) = %d, %v; want 0, ErrInvalidBudget", excess, err)
		}
		if a.Limit() != 2*pageSize || a.Available() != 2*pageSize {
			t.Errorf("Limit=%d Available=%d after refusal, want both %d",
				a.Limit(), a.Available(), 2*pageSize)
		}
	})
}

// TestAllocator_TransferTo_MovesHeadroom pins that a transfer makes dst admit
// what it refused, debits the source by the same amount, and conserves the
// total. Both construction orders run, covering both lock-order branches.
func TestAllocator_TransferTo_MovesHeadroom(t *testing.T) {
	for _, srcFirst := range []bool{true, false} {
		name := "source constructed first"
		if !srcFirst {
			name = "destination constructed first (lock order swaps)"
		}
		t.Run(name, func(t *testing.T) {
			var src, dst *budgetAllocator
			mk := func(n int64) *budgetAllocator {
				t.Helper()
				a, err := newBudgetAllocator(n)
				if err != nil {
					t.Fatalf("newBudgetAllocator(%d): %v", n, err)
				}
				return a
			}
			if srcFirst {
				src = mk(4 * pageSize)
				dst = mk(pageSize)
			} else {
				dst = mk(pageSize)
				src = mk(4 * pageSize)
			}

			hold, err := dst.admitData(material())
			if err != nil {
				t.Fatalf("New (filling dst): %v", err)
			}
			defer hold.Destroy()
			if _, err := dst.NewSized(32); !errors.Is(err, ErrBudgetExhausted) {
				t.Fatalf("dst.NewSized before the transfer = %v, want ErrBudgetExhausted", err)
			}

			total := src.Limit() + dst.Limit()
			if err := src.TransferTo(dst, 2*pageSize); err != nil {
				t.Fatalf("TransferTo: %v", err)
			}
			if src.Limit() != 2*pageSize || src.Available() != 2*pageSize {
				t.Errorf("src Limit=%d Available=%d, want both %d", src.Limit(), src.Available(), 2*pageSize)
			}
			if dst.Limit() != 3*pageSize || dst.InUse() != pageSize || dst.Available() != 2*pageSize {
				t.Errorf("dst Limit=%d InUse=%d Available=%d, want %d, %d, %d",
					dst.Limit(), dst.InUse(), dst.Available(), 3*pageSize, pageSize, 2*pageSize)
			}
			if got := src.Limit() + dst.Limit(); got != total {
				t.Errorf("budgets sum to %d after the transfer, want the conserved %d", got, total)
			}

			e, err := dst.admitSized(32)
			if err != nil {
				t.Fatalf("dst.NewSized after the transfer: %v (the moved headroom was not admissible)", err)
			}
			e.Destroy()
		})
	}
}

// TestAllocator_TransferTo_RefusedWithoutHeadroom pins that a source cannot
// donate headroom it lacks, that the refusal leaves both allocators untouched,
// and that the same transfer succeeds once headroom is freed.
func TestAllocator_TransferTo_RefusedWithoutHeadroom(t *testing.T) {
	src, err := newBudgetAllocator(2 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	dst, err := newBudgetAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e1, err := src.admitData(material())
	if err != nil {
		t.Fatalf("New(e1): %v", err)
	}
	e2, err := src.admitData(material())
	if err != nil {
		t.Fatalf("New(e2): %v", err)
	}
	defer e2.Destroy()

	err = src.TransferTo(dst, pageSize)
	if !errors.Is(err, ErrBudgetInUse) {
		t.Fatalf("TransferTo without headroom = %v, want ErrBudgetInUse", err)
	}
	var le *BudgetInUseError
	if !errors.As(err, &le) {
		t.Fatalf("err is not a *BudgetInUseError: %v", err)
	}
	// Requested is the budget the SOURCE would have been left with.
	if le.Requested != pageSize || le.InUse != 2*pageSize || le.Limit != 2*pageSize {
		t.Errorf("BudgetInUseError = %+v, want Requested=%d InUse=%d Limit=%d",
			le, pageSize, 2*pageSize, 2*pageSize)
	}
	if src.Limit() != 2*pageSize || src.Available() != 0 {
		t.Errorf("src Limit=%d Available=%d after refusal, want %d and 0", src.Limit(), src.Available(), 2*pageSize)
	}
	if dst.Limit() != pageSize || dst.Available() != pageSize {
		t.Errorf("dst Limit=%d Available=%d after refusal, want both %d (the destination must not be credited)",
			dst.Limit(), dst.Available(), pageSize)
	}

	// CONTROL: with headroom freed, the identical transfer succeeds.
	e1.Destroy()
	if err := src.TransferTo(dst, pageSize); err != nil {
		t.Fatalf("TransferTo after freeing headroom: %v", err)
	}
	if src.Limit() != pageSize || dst.Limit() != 2*pageSize {
		t.Errorf("after the control transfer src.Limit=%d dst.Limit=%d, want %d and %d",
			src.Limit(), dst.Limit(), pageSize, 2*pageSize)
	}
}

func TestAllocator_TransferTo_Invalid(t *testing.T) {
	a, err := newBudgetAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	b, err := newBudgetAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	t.Run("non-positive amounts", func(t *testing.T) {
		for _, n := range []int64{0, -1, -pageSize} {
			if err := a.TransferTo(b, n); !errors.Is(err, ErrInvalidTransfer) {
				t.Errorf("TransferTo(n=%d) = %v, want ErrInvalidTransfer", n, err)
			}
		}
	})
	t.Run("nil destination", func(t *testing.T) {
		if err := a.TransferTo(nil, pageSize); !errors.Is(err, ErrInvalidTransfer) {
			t.Errorf("TransferTo(nil) = %v, want ErrInvalidTransfer", err)
		}
	})
	t.Run("destination is the source", func(t *testing.T) {
		// Bounded, because the failure this guards against is not a wrong
		// answer but taking the same non-reentrant lock twice and hanging.
		var wg sync.WaitGroup
		wg.Add(1)
		var got error
		go func() {
			defer wg.Done()
			got = a.TransferTo(a, pageSize)
		}()
		waitBounded(t, &wg, 20*time.Second, "self-transfer")
		if !errors.Is(got, ErrInvalidTransfer) {
			t.Errorf("TransferTo(self) = %v, want ErrInvalidTransfer", got)
		}
	})

	if a.Limit() != 4*pageSize || b.Limit() != 4*pageSize {
		t.Errorf("a.Limit=%d b.Limit=%d after refused transfers, want both %d",
			a.Limit(), b.Limit(), 4*pageSize)
	}
}

// TestAllocator_TransferTo_DestinationOverflow pins that a credit which would
// overflow dst's int64 budget is refused before the source is debited.
func TestAllocator_TransferTo_DestinationOverflow(t *testing.T) {
	src, err := newBudgetAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	dst, err := newBudgetAllocator(math.MaxInt64)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := src.TransferTo(dst, pageSize); !errors.Is(err, ErrInvalidBudget) {
		t.Fatalf("TransferTo into an int64-saturated budget = %v, want ErrInvalidBudget", err)
	}
	// Refused before anything was debited: the source keeps its headroom.
	if src.Limit() != 4*pageSize || src.Available() != 4*pageSize {
		t.Errorf("src Limit=%d Available=%d, want both %d", src.Limit(), src.Available(), 4*pageSize)
	}
	if dst.Limit() != math.MaxInt64 {
		t.Errorf("dst.Limit = %d, want the unchanged %d", dst.Limit(), int64(math.MaxInt64))
	}
}

// TestAllocator_TransferTo_NeverInBoth pins the direction of the transfer's
// intermediate state: the moved bytes may be in neither allocator, never both.
// The sampler reads dst then src, opposite to the write order (debit src, then
// credit dst), so with correct ordering the sum can never exceed the total and
// reversed writes let it. Transfers run one way only, since a returning
// transfer writes in the other order.
func TestAllocator_TransferTo_NeverInBoth(t *testing.T) {
	const moves = 4000
	src, err := newBudgetAllocator(moves * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	dst, err := newBudgetAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	total := src.Limit() + dst.Limit()

	var samples, violations atomic.Int64
	// The sampler has a floor of its own and outlives the transfers, so the run
	// cannot pass having sampled nothing.
	const minSamples = 1000
	transfersDone := make(chan struct{})
	samplerReady := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			if i >= minSamples {
				select {
				case <-transfersDone:
					return
				default:
				}
			}
			// Destination first, source second; see the doc comment.
			d := dst.free.Load()
			s := src.free.Load()
			if samples.Add(1) == 1 {
				// The transfers wait for this.
				close(samplerReady)
			}
			if d+s > total {
				violations.Add(1)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(transfersDone)
		<-samplerReady
		for i := 0; i < moves; i++ {
			if err := src.TransferTo(dst, pageSize); err != nil {
				t.Errorf("TransferTo #%d: %v", i, err)
				return
			}
		}
	}()

	waitBounded(t, &wg, 60*time.Second, "the one-way transfer run")

	if n := violations.Load(); n != 0 {
		t.Errorf("observed %d samples where the moved bytes were in BOTH allocators at once", n)
	}
	// Controls: the sampler must have cleared its floor, and the run must
	// actually have moved everything it set out to.
	if n := samples.Load(); n < minSamples {
		t.Errorf("the sampler took %d samples, want at least %d; this test asserted almost nothing", n, minSamples)
	}
	if got := src.Limit() + dst.Limit(); got != total {
		t.Errorf("budgets sum to %d, want the conserved %d", got, total)
	}
	if src.Limit() != 0 || dst.Limit() != total {
		t.Errorf("src.Limit=%d dst.Limit=%d after draining src, want 0 and %d", src.Limit(), dst.Limit(), total)
	}
	t.Logf("samples=%d", samples.Load())
}

// TestAllocator_StaysWithinItsCachelineBudget pins the budget an Allocator
// shares (allocatorState) at no more than 64 bytes, with free and limit in the
// same line. 64 is a fixed budget, not a discovered line size. If it fails, ask
// whether the new field belongs on the hot type at all; see
// docs/locked-memory-budget/engineering.md, Test strategy.
func TestAllocator_StaysWithinItsCachelineBudget(t *testing.T) {
	const line = 64

	got := unsafe.Sizeof(allocatorState{})
	if got > line {
		t.Errorf("allocatorState is %d bytes, over the %d-byte cacheline budget: the field just added pushed the type into a second line — see this test's comment before widening the budget",
			got, line)
	}
	// free and limit must share a line; the lock-free paths read them together.
	free, limit := unsafe.Offsetof(allocatorState{}.free), unsafe.Offsetof(allocatorState{}.limit)
	if free/line != limit/line {
		t.Errorf("free is at offset %d and limit at %d, in different %d-byte lines: the two words admission and refusal read together are now split",
			free, limit, line)
	}
	t.Logf("allocatorState size=%d budget=%d free@%d limit@%d", got, line, free, limit)
}

// retuneActors is the goroutines contending for pages in each round of
// [TestAllocator_Retune_RacesAdmission], besides the retuner. A round holds up
// to retuneActors locked pages, so RLIMIT_MEMLOCK must allow that many; below
// it rounds fail with ErrLockedMemoryUnavailable ("unexpected NewSized err").
const retuneActors = 8

// retuneShape is one kind of arranged round, sized in pages: every claim in a
// round is exactly one page.
type retuneShape struct {
	name string
	// limit is the opening budget; the retuner raises it by the contested page
	// before the contest opens.
	limit int64
	// admit is how many actors attempt exactly one admission each.
	admit int
	// drain is how many actors destroy one pre-held enclave inside the window.
	drain int
}

// supply is the budget plus the raised page, less the pre-held pages. Pages
// returned by draining actors are not counted, so no claim depends on when a
// Destroy lands.
func (sh retuneShape) supply() int64 { return sh.limit + 1 - int64(sh.drain) }

// demand is the page claims attempted: one per admitting actor, plus the
// retuner's withdrawal.
func (sh retuneShape) demand() int64 { return int64(sh.admit) + 1 }

// granted is how many claims must succeed under any interleaving:
// min(supply, demand). No more, since a page cannot be granted twice; no fewer,
// since a claim is refused only when the counter reads zero, and nothing returns
// a page in an over-subscribed shape.
func (sh retuneShape) granted() int64 {
	if sh.supply() < sh.demand() {
		return sh.supply()
	}
	return sh.demand()
}

// retuneRound is the state of one arranged round. Every field is written by a
// single goroutine and read by the coordinator after the join, except the
// counters, which are atomic because the actors share them.
type retuneRound struct {
	shape retuneShape
	a     *budgetAllocator
	held  []*Memory // one per draining actor; destroyed inside the window
	got   []*Memory // one per admitting actor; nil where it was refused

	wg      sync.WaitGroup
	arrived atomic.Int32

	admitted atomic.Int64
	refused  atomic.Int64
	lowered  atomic.Bool
}

// line parks the caller until every participant arrives, so claims race each
// other. It fails the test on timeout rather than returning quietly, since an
// unsynchronized round would measure something else.
func (rd *retuneRound) line(t *testing.T) bool {
	t.Helper()
	const participants = retuneActors + 1
	rd.arrived.Add(1)
	deadline := time.Now().Add(30 * time.Second)
	for rd.arrived.Load() < participants {
		if time.Now().After(deadline) {
			t.Errorf("%s round: %d of %d participants reached the line; the contest was never synchronized and this round proves nothing",
				rd.shape.name, rd.arrived.Load(), participants)
			return false
		}
		runtime.Gosched()
	}
	return true
}

// retuneTally counts what the arranged rounds did, for the vacuity controls.
type retuneTally struct {
	admitted     atomic.Int64
	refusedAdmit atomic.Int64
	raised       atomic.Int64
	lowered      atomic.Int64
	refusedLower atomic.Int64
	overCommit   atomic.Int64
}

// TestAllocator_Retune_RacesAdmission pins that a budget lowering and an
// admission racing for the same page are linearized: exactly one gets it.
//
// The contest is arranged, not a storm: a storm's lowerings starve when
// admitting goroutines hold pages across preemption, so coverage depended on
// load. Each round releases a fixed cast from one line (one-page admissions,
// one-page drains, and a retuner that raises by a page and then lowers by one),
// so min(supply, demand) claims must be granted in any order. Shapes:
//
//   - slack: supply covers demand; every admission and the lowering succeed.
//   - contested: two pages short; exactly two claims are refused. Detecting a
//     double-spend here needs more than one core.
//   - draining: destroys land inside the window; accounting must stay exact.
//
// Each round asserts free never goes negative, exactly granted() claims
// succeed, every actor recorded an outcome, InUse and Limit match the outcome,
// and the allocator is whole once its enclaves are destroyed.
func TestAllocator_Retune_RacesAdmission(t *testing.T) {
	var tally retuneTally

	shapes := []retuneShape{
		// Supply exactly covers demand: 8 pages plus the raised one against 8
		// admissions plus the withdrawal.
		{name: "slack", limit: retuneActors, admit: retuneActors},
		// Two pages short: 6 plus the raised one against 8 admissions plus the
		// withdrawal, so exactly two claims must be refused.
		{name: "contested", limit: retuneActors - 2, admit: retuneActors},
		// Half the actors return a page while the other half take one: 8 pages
		// plus the raised one, less the 4 the pre-held enclaves hold, against 4
		// admissions plus the withdrawal.
		{name: "draining", limit: retuneActors, admit: retuneActors / 2, drain: retuneActors / 2},
	}

	for _, sh := range shapes {
		t.Run(sh.name, func(t *testing.T) {
			runRetuneShape(t, sh, &tally)
		})
	}

	if n := tally.overCommit.Load(); n != 0 {
		t.Errorf("the allocator over-committed %d times: a lowering and an admission both took the same page", n)
	}
	// Controls: the shapes guarantee a successful lowering (slack, draining) and a
	// refused admission (contested), so these fail only when the code is broken.
	if tally.admitted.Load() == 0 {
		t.Error("no allocation was ever admitted; this test asserted nothing")
	}
	if tally.lowered.Load() == 0 {
		t.Error("no lowering ever succeeded; the shrinking half of the retune path was never exercised")
	}
	if tally.raised.Load() == 0 {
		t.Error("no raise ever ran; the retuners did nothing")
	}
	if tally.refusedAdmit.Load() == 0 {
		t.Error("nothing was ever refused admission; the goroutines never contended and the race was not exercised")
	}
	t.Logf("admitted=%d refusedAdmit=%d raised=%d lowered=%d refusedLower=%d",
		tally.admitted.Load(), tally.refusedAdmit.Load(), tally.raised.Load(),
		tally.lowered.Load(), tally.refusedLower.Load())
}

// runRetuneShape runs one shape's rounds against a long-lived cast of
// goroutines, released round by round, checking each round and adding to the
// tally. An already-running cast is likelier to reach the line together.
func runRetuneShape(t *testing.T, sh retuneShape, tally *retuneTally) {
	// Harness self-checks on the shape's arithmetic.
	if sh.admit+sh.drain != retuneActors {
		t.Fatalf("shape %s: %d admitting + %d draining actors, want exactly %d",
			sh.name, sh.admit, sh.drain, retuneActors)
	}
	if sh.supply() < sh.demand() && sh.drain != 0 {
		t.Fatalf("shape %s: an over-subscribed shape must not drain; a page returned mid-round makes the granted count depend on when the Destroy landed", sh.name)
	}

	const rounds = 200

	release := make([]chan struct{}, rounds)
	for i := range release {
		release[i] = make(chan struct{})
	}
	// rds[r] is published before release[r] is closed, and read only after the
	// receive, so the close is the happens-before edge. A nil entry means the
	// shape gave up after a failing round and the cast should leave.
	rds := make([]*retuneRound, rounds)

	// witness samples the admission counter, called at every point where a
	// racing pair could have double-spent a page.
	witness := func(a *budgetAllocator) {
		if a.free.Load() < 0 {
			tally.overCommit.Add(1)
		}
	}

	var lifetime sync.WaitGroup
	// participate is one member of the cast: idx in [0, retuneActors) is an
	// actor, which admits or drains according to the shape, and idx ==
	// retuneActors is the retuner.
	participate := func(idx int) {
		defer lifetime.Done()
		for r := 0; r < rounds; r++ {
			<-release[r]
			rd := rds[r]
			if rd == nil {
				return
			}
			func() {
				defer rd.wg.Done()
				retuner := idx == retuneActors
				if retuner {
					// Raise before the line: a raise has nothing to race, and doing it
					// inside the window gives the admissions a head start, so the
					// withdrawal would never contest the page.
					if err := rd.a.SetLimit((rd.shape.limit + 1) * pageSize); err != nil {
						t.Errorf("%s round %d: SetLimit(raise): %v", rd.shape.name, r, err)
						// Arrive anyway, or the rest of the cast stalls until timeout.
						_ = rd.line(t)
						return
					}
					tally.raised.Add(1)
				}
				if !rd.line(t) {
					return
				}
				switch {
				case retuner:
					switch err := rd.a.SetLimit(rd.shape.limit * pageSize); {
					case err == nil:
						rd.lowered.Store(true)
						tally.lowered.Add(1)
					case errors.Is(err, ErrBudgetInUse):
						tally.refusedLower.Add(1)
					default:
						t.Errorf("%s round %d: unexpected SetLimit(lower) err: %v", rd.shape.name, r, err)
					}
					witness(rd.a)
				case idx < rd.shape.admit:
					e, err := rd.a.admitSized(32)
					witness(rd.a)
					switch {
					case err == nil:
						rd.got[idx] = e
						rd.admitted.Add(1)
						tally.admitted.Add(1)
					case errors.Is(err, ErrBudgetExhausted):
						rd.refused.Add(1)
						tally.refusedAdmit.Add(1)
					default:
						t.Errorf("%s round %d: unexpected NewSized err: %v", rd.shape.name, r, err)
					}
					witness(rd.a)
				default:
					rd.held[idx-rd.shape.admit].Destroy()
					witness(rd.a)
				}
			}()
		}
	}
	lifetime.Add(retuneActors + 1)
	for i := 0; i <= retuneActors; i++ {
		go participate(i)
	}

	var shAdmitted, shRefusedAdmit, shLowered int64
	// closeFrom is the first round the cast must be let out of rather than run.
	// It stays at rounds for a clean run.
	closeFrom := rounds
	for r := 0; r < rounds; r++ {
		a, err := newBudgetAllocator(sh.limit * pageSize)
		if err != nil {
			t.Errorf("%s round %d: NewAllocator: %v", sh.name, r, err)
			closeFrom = r
			break
		}
		rd := &retuneRound{
			shape: sh,
			a:     a,
			held:  make([]*Memory, sh.drain),
			got:   make([]*Memory, sh.admit),
		}
		bad := false
		for i := range rd.held {
			e, err := a.admitSized(32)
			if err != nil {
				t.Errorf("%s round %d: pre-held enclave %d: %v", sh.name, r, i, err)
				bad = true
				break
			}
			rd.held[i] = e
		}
		// The arranged starting state, checked before anyone is released: a
		// round that opens on the wrong headroom proves something other than
		// what its arithmetic says it does.
		if !bad {
			if got, want := a.Available(), (sh.limit-int64(sh.drain))*pageSize; got != want {
				t.Errorf("%s round %d: opened with %d bytes admissible, want %d", sh.name, r, got, want)
				bad = true
			}
		}
		if bad {
			for _, e := range rd.held {
				if e != nil {
					e.Destroy()
				}
			}
			closeFrom = r
			break
		}

		rd.wg.Add(retuneActors + 1)
		rds[r] = rd
		close(release[r])
		waitBounded(t, &rd.wg, 60*time.Second, sh.name+" round")

		checkRetuneRound(t, r, rd)
		shAdmitted += rd.admitted.Load()
		shRefusedAdmit += rd.refused.Load()
		if rd.lowered.Load() {
			shLowered++
		}

		for _, e := range rd.got {
			if e != nil {
				e.Destroy()
			}
		}
		if got := a.InUse(); got != 0 {
			t.Errorf("%s round %d: InUse = %d once every enclave was destroyed, want 0 (a reservation leaked)", sh.name, r, got)
		}
		if a.Available() != a.Limit() {
			t.Errorf("%s round %d: Available = %d against Limit %d, want them equal", sh.name, r, a.Available(), a.Limit())
		}

		if t.Failed() {
			// One diagnosed round is enough.
			closeFrom = r + 1
			break
		}
	}
	for k := closeFrom; k < rounds; k++ {
		close(release[k])
	}
	waitBounded(t, &lifetime, 60*time.Second, sh.name+" cast")

	t.Logf("%s: rounds=%d supply=%d demand=%d granted=%d/round admitted=%d refusedAdmit=%d lowered=%d",
		sh.name, closeFrom, sh.supply(), sh.demand(), sh.granted(), shAdmitted, shRefusedAdmit, shLowered)
}

// checkRetuneRound asserts one completed round's arithmetic, which holds on
// every host and interleaving.
func checkRetuneRound(t *testing.T, r int, rd *retuneRound) {
	sh := rd.shape
	admitted := rd.admitted.Load()
	refused := rd.refused.Load()
	lowered := rd.lowered.Load()

	if free := rd.a.free.Load(); free < 0 {
		t.Errorf("%s round %d: free = %d after the round: a lowering and an admission both took the same page",
			sh.name, r, free)
	}
	// Every actor accounted for, so an early return cannot pass as a refusal.
	if got := admitted + refused; got != int64(sh.admit) {
		t.Errorf("%s round %d: %d of %d admitting actors recorded an outcome",
			sh.name, r, got, sh.admit)
	}
	if got := admitted + oneIf(lowered); got != sh.granted() {
		t.Errorf("%s round %d: %d page claims granted (%d admissions + %d lowering), want exactly %d from a supply of %d against a demand of %d",
			sh.name, r, got, admitted, oneIf(lowered), sh.granted(), sh.supply(), sh.demand())
	}
	if got, want := rd.a.InUse(), admitted*pageSize; got != want {
		t.Errorf("%s round %d: InUse = %d, want %d (%d admitted enclaves, everything pre-held destroyed)",
			sh.name, r, got, want, admitted)
	}
	// A refused withdrawal changes nothing, so the budget is still the raised
	// one; a successful withdrawal puts it back where the round started.
	wantLimit := sh.limit
	outcome := "succeeded"
	if !lowered {
		wantLimit++
		outcome = "was refused"
	}
	if got := rd.a.Limit(); got != wantLimit*pageSize {
		t.Errorf("%s round %d: Limit = %d, want %d (the withdrawal %s)",
			sh.name, r, got, wantLimit*pageSize, outcome)
	}
}

// oneIf counts a boolean outcome as the one page claim it represents.
func oneIf(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// TestAllocator_Retune_LoweringLosesTheContestedPage stages the lowering vs.
// admission race deterministically through the stalled seam. With one page of
// headroom:
//
//  1. SetLimit(0) reads free = one page and parks before its compare-and-swap.
//  2. The test admits that page, which must succeed.
//  3. The withdrawal resumes, its swap fails, it re-reads, and refuses.
//
// Afterwards the admission holds the page, the budget is unchanged, and free is
// zero, not negative. The reverse window (an admission parked) is not staged,
// since that would put a seam on the admission path.
func TestAllocator_Retune_LoweringLosesTheContestedPage(t *testing.T) {
	a, err := newBudgetAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	parked := make(chan struct{})
	resume := make(chan struct{})
	var (
		park    sync.Once
		release sync.Once
	)
	// Idempotent: Cleanup calls it too, so a Fatalf while parked does not leave
	// the goroutine blocked holding a.mu.
	releaseParked := func() { release.Do(func() { close(resume) }) }
	t.Cleanup(releaseParked)
	// Set before the goroutine starts, so it needs no synchronization. One-shot
	// because the loop reaches the seam again after its swap fails, and a second
	// close(parked) would panic.
	a.stalled = func() {
		park.Do(func() {
			close(parked)
			<-resume
		})
	}

	var (
		lowerErr error
		withdraw sync.WaitGroup
	)
	withdraw.Add(1)
	go func() {
		defer withdraw.Done()
		lowerErr = a.SetLimit(0)
	}()

	select {
	case <-parked:
	case <-time.After(15 * time.Second):
		// Without the seam the contest was never staged.
		t.Fatalf("the withdrawal never reached the seam in withdrawLocked; the contest was never staged and this test proves nothing")
	}

	// The conflicting admission, made while the withdrawal is parked between
	// its read of the counter and the swap that acts on it.
	e, err := a.admitSized(32)
	if err != nil {
		t.Fatalf("the admission that must win the contested page was refused: %v", err)
	}
	if free := a.free.Load(); free != 0 {
		t.Errorf("free = %d once the page was admitted, want 0", free)
	}

	releaseParked()
	waitBounded(t, &withdraw, 30*time.Second, "the parked withdrawal")

	// The surviving state first, the loser's error second.
	if free := a.free.Load(); free != 0 {
		t.Errorf("free = %d, want 0: the lowering and the admission both took the same page", free)
	}
	if got, want := a.Limit(), pageSize; got != want {
		t.Errorf("Limit = %d, want %d: a refused lowering must leave the budget exactly as it found it", got, want)
	}
	if got, want := a.InUse(), pageSize; got != want {
		t.Errorf("InUse = %d, want %d: the admitted enclave's reservation", got, want)
	}
	if lowerErr == nil {
		t.Error("SetLimit(0) reported success although the page it had decided to take was admitted first: the budget and the enclave both hold it")
	} else if !errors.Is(lowerErr, ErrBudgetInUse) {
		t.Errorf("SetLimit(0) = %v, want a BudgetInUseError matching ErrBudgetInUse", lowerErr)
	}

	// And the reservation still returns, so the refusal left nothing behind.
	e.Destroy()
	if got, want := a.Available(), pageSize; got != want {
		t.Errorf("Available = %d after Destroy, want %d", got, want)
	}
}

// TestAllocator_TransferTo_ConcurrentOppositeDirections pins that opposing
// transfers between two allocators cannot deadlock (the wait is bounded), and
// that under concurrent allocation neither over-commits and the total budget is
// conserved.
func TestAllocator_TransferTo_ConcurrentOppositeDirections(t *testing.T) {
	a, err := newBudgetAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	b, err := newBudgetAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	total := a.Limit() + b.Limit()

	var (
		moved       atomic.Int64
		refused     atomic.Int64
		admitted    atomic.Int64
		refusedBoth atomic.Int64
		overCommit  atomic.Int64
	)
	witness := func() {
		if a.free.Load() < 0 || b.free.Load() < 0 {
			overCommit.Add(1)
		}
	}

	// The allocations bound the run and the transfers stop when they do. Bounded
	// transfers can finish before the allocators are scheduled (GOMAXPROCS=1), and
	// unbounded coordination lets transfers drain one side so nothing is admitted;
	// either passes having asserted nothing.
	const allocIterations = 400
	var wg sync.WaitGroup

	start := make(chan struct{})
	allocDone := make(chan struct{})
	var allocsLeft atomic.Int64
	allocsLeft.Store(2)

	transfer := func(from, to *budgetAllocator) {
		defer wg.Done()
		<-start
		for {
			select {
			case <-allocDone:
				return
			default:
			}
			switch err := from.TransferTo(to, pageSize); {
			case err == nil:
				moved.Add(1)
			case errors.Is(err, ErrBudgetInUse):
				refused.Add(1)
			default:
				t.Errorf("unexpected TransferTo err: %v", err)
				return
			}
			witness()
		}
	}
	wg.Add(2)
	go transfer(a, b)
	go transfer(b, a)

	// alloc falls back to the other allocator on refusal, since transfers can
	// drain either side. That makes admission likely, not certain: the whole budget
	// can migrate between the two attempts, so refusedBoth is logged, not asserted
	// zero.
	alloc := func(primary, fallback *budgetAllocator) {
		defer wg.Done()
		// Closed on every exit path, so a failing allocator releases the transfers.
		defer func() {
			if allocsLeft.Add(-1) == 0 {
				close(allocDone)
			}
		}()
		<-start
		for i := 0; i < allocIterations; i++ {
			e, err := primary.admitSized(32)
			witness()
			if err != nil {
				if !errors.Is(err, ErrBudgetExhausted) {
					t.Errorf("unexpected NewSized err: %v", err)
					return
				}
				if e, err = fallback.admitSized(32); err != nil {
					if !errors.Is(err, ErrBudgetExhausted) {
						t.Errorf("unexpected fallback NewSized err: %v", err)
						return
					}
					refusedBoth.Add(1)
					witness()
					continue
				}
			}
			admitted.Add(1)
			e.Destroy()
			witness()
		}
	}
	wg.Add(2)
	go alloc(a, b)
	go alloc(b, a)

	close(start)
	waitBounded(t, &wg, 60*time.Second, "opposed transfers")

	if n := overCommit.Load(); n != 0 {
		t.Errorf("an allocator over-committed %d times while its budget was being rebalanced", n)
	}
	if got := a.Limit() + b.Limit(); got != total {
		t.Errorf("budgets sum to %d, want the conserved %d: a transfer created or destroyed headroom", got, total)
	}
	if a.Limit() < 0 || b.Limit() < 0 {
		t.Errorf("a.Limit=%d b.Limit=%d; a budget went negative", a.Limit(), b.Limit())
	}
	// Controls: the run must actually have moved headroom, and must actually
	// have allocated against the moving budgets.
	if moved.Load() == 0 {
		t.Error("no transfer ever succeeded; this test asserted nothing about transfers")
	}
	if admitted.Load() == 0 {
		t.Error("no allocation was ever admitted; the transfers never raced an admission")
	}
	t.Logf("moved=%d refused=%d admitted=%d refusedBoth=%d finalLimits=%d/%d",
		moved.Load(), refused.Load(), admitted.Load(), refusedBoth.Load(), a.Limit(), b.Limit())
}

// TestInUseFrom covers inUseFrom at its boundaries: a negative free beside a
// large limit (the only pairs that can wrap) and free above limit (a stale read
// across a lowering) must both be rejected, alongside ordinary consistent pairs.
func TestInUseFrom(t *testing.T) {
	const max = int64(math.MaxInt64)
	for _, tc := range []struct {
		name        string
		limit, free int64
		want        int64
		ok          bool
	}{
		{"fresh allocator", 4 * pageSize, 4 * pageSize, 0, true},
		{"one page reserved", 4 * pageSize, 3 * pageSize, pageSize, true},
		{"budget fully reserved", pageSize, 0, pageSize, true},
		{"quiesced and idle", 0, 0, 0, true},
		{"over-subscribed by a page", pageSize, -pageSize, 2 * pageSize, true},
		{"the largest expressible budget, idle", max, max, 0, true},
		{"the largest expressible budget, fully reserved", max, 0, max, true},
		{"widest representable pair", max - pageSize, -pageSize, max, true},
		// One byte past it: this is the pair the refusal path can read in the
		// window between a limit being raised and its headroom being credited.
		{"one byte too wide", max, -1, 0, false},
		{"a page too wide", max, -pageSize, 0, false},
		{"as wide as int64 gets", max, -max, 0, false},
		// The stale skew: free read before a lowering, beside the lowered limit.
		// Nothing wraps; the pair is just inconsistent.
		{"stale headroom beside a lowered limit", 0, 2 * pageSize, 0, false},
		{"stale headroom a byte above the limit", pageSize, pageSize + 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := inUseFrom(tc.limit, tc.free)
			if ok != tc.ok {
				t.Fatalf("inUseFrom(%d, %d) ok = %v, want %v", tc.limit, tc.free, ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Errorf("inUseFrom(%d, %d) = %d, want %d", tc.limit, tc.free, got, tc.want)
			}
			if got < 0 {
				t.Errorf("inUseFrom(%d, %d) = %d; a reserved-byte count is never negative", tc.limit, tc.free, got)
			}
		})
	}
}

// TestAllocator_budgetSnapshot_FallsBackWhenSkewed hands budgetSnapshot a stale
// negative free beside a raised limit, a pair the settled allocator is not in,
// and pins that the locked fallback returns the exact settled figures.
func TestAllocator_budgetSnapshot_FallsBackWhenSkewed(t *testing.T) {
	a, err := newBudgetAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	// A settled allocator with the largest expressible budget and one page
	// reserved: limit MaxInt64, free MaxInt64-pageSize.
	if err := a.SetLimit(math.MaxInt64); err != nil {
		t.Fatalf("SetLimit: %v", err)
	}
	a.free.Add(-pageSize)

	t.Run("representable pair takes the fast path", func(t *testing.T) {
		limit, inUse := a.budgetSnapshot(a.free.Load())
		if limit != math.MaxInt64 || inUse != pageSize {
			t.Errorf("budgetSnapshot = (%d, %d), want (%d, %d)", limit, inUse, int64(math.MaxInt64), pageSize)
		}
	})

	t.Run("skewed pair falls back to the locked read", func(t *testing.T) {
		// -pageSize is what free reads as while an over-subscribed allocator is
		// mid-raise. Against a MaxInt64 limit the difference does not fit, and
		// the unguarded subtraction returns a negative byte count.
		limit, inUse := a.budgetSnapshot(-pageSize)
		if inUse < 0 {
			t.Fatalf("budgetSnapshot reported InUse = %d; a reserved-byte count is never negative", inUse)
		}
		if limit != math.MaxInt64 || inUse != pageSize {
			t.Errorf("budgetSnapshot = (%d, %d), want the allocator's settled (%d, %d)",
				limit, inUse, int64(math.MaxInt64), pageSize)
		}
	})
}

// TestAllocator_budgetSnapshot_FallsBackWhenLoweredUnderAStaleRead pins the
// other skew: free read before SetLimit(0) on an idle allocator, paired with the
// new zero limit, would report InUse as -2 pages. The fallback must return the
// settled (0, 0).
func TestAllocator_budgetSnapshot_FallsBackWhenLoweredUnderAStaleRead(t *testing.T) {
	a, err := newBudgetAllocator(2 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	stale := a.free.Load()
	if err := a.SetLimit(0); err != nil {
		t.Fatalf("SetLimit(0) on an empty allocator: %v", err)
	}

	limit, inUse := a.budgetSnapshot(stale)
	if inUse < 0 {
		t.Fatalf("budgetSnapshot reported InUse = %d against a limit of %d; a "+
			"reserved-byte count is never negative", inUse, limit)
	}
	if limit != 0 || inUse != 0 {
		t.Errorf("budgetSnapshot = (%d, %d), want the allocator's settled (0, 0)", limit, inUse)
	}
}

// TestAllocator_Refusal_NeverReportsNegativeInUse drives the real window: an
// over-subscribed allocator is raised to MaxInt64 and dropped back repeatedly
// while other goroutines collect refusals, none of which may report a negative
// InUse. It needs parallelism to hit the window reliably; the budgetSnapshot
// tests cover it deterministically. It checks that the count is possible, not
// that it is exact.
func TestAllocator_Refusal_NeverReportsNegativeInUse(t *testing.T) {
	a, err := newBudgetAllocator(2 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	// One page reserved, then a budget of zero: free is now -pageSize and the
	// allocator refuses everything.
	hold, err := a.admitData(material())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer hold.Destroy()
	excess, err := a.ForceLimit(0)
	if err != nil || excess != pageSize {
		t.Fatalf("ForceLimit(0) = %d, %v; want %d, nil", excess, err, pageSize)
	}

	const (
		retuneIterations = 4000
		minRefusals      = 500
	)
	var (
		refusals atomic.Int64
		negative atomic.Int64
		maxInUse atomic.Int64
	)
	var wg sync.WaitGroup
	start := make(chan struct{})
	retunersDone := make(chan struct{})
	refusersDone := make(chan struct{})
	var retunersLeft, refusersLeft atomic.Int64
	retunersLeft.Store(2)
	refusersLeft.Store(2)

	// The retuners carry both floors (retuneIterations and minRefusals), and the
	// refusers sample until the last retuner stops. A refuser iteration may be
	// admitted rather than refused, so iterations alone do not bound the evidence,
	// and refusers that stopped at the target could collect it from the static pair
	// before any retune lands.
	retune := func() {
		defer wg.Done()
		defer func() {
			if retunersLeft.Add(-1) == 0 {
				close(retunersDone)
			}
		}()
		<-start
		// Either floor alone permits a vacuous run.
		for i := 0; ; i++ {
			if i >= retuneIterations && refusals.Load() >= minRefusals {
				return
			}
			// refusersDone closes when the refusers exit, which before the retuners
			// finish happens only on an error.
			select {
			case <-refusersDone:
				return
			default:
			}
			// Raising to MaxInt64 is what widens the difference past int64;
			// ForceLimit back to zero restores the negative free the next raise
			// needs.
			if _, err := a.ForceLimit(math.MaxInt64); err != nil {
				t.Errorf("ForceLimit(max): %v", err)
				return
			}
			if _, err := a.ForceLimit(0); err != nil {
				t.Errorf("ForceLimit(0): %v", err)
				return
			}
		}
	}
	wg.Add(2)
	go retune()
	go retune()

	refuse := func() {
		defer wg.Done()
		defer func() {
			if refusersLeft.Add(-1) == 0 {
				close(refusersDone)
			}
		}()
		<-start
		// Sample until the last retuner has stopped.
		for {
			select {
			case <-retunersDone:
				return
			default:
			}
			e, err := a.admitSized(32)
			if err == nil {
				// The budget was momentarily at MaxInt64; give it straight back.
				e.Destroy()
				continue
			}
			var be *BudgetError
			if !errors.As(err, &be) {
				t.Errorf("unexpected NewSized err: %v", err)
				return
			}
			refusals.Add(1)
			if be.InUse < 0 {
				negative.Add(1)
			}
			for {
				m := maxInUse.Load()
				if be.InUse <= m || maxInUse.CompareAndSwap(m, be.InUse) {
					break
				}
			}
		}
	}
	wg.Add(2)
	go refuse()
	go refuse()

	close(start)
	waitBounded(t, &wg, 60*time.Second, "the refusal/raise race")

	if n := negative.Load(); n != 0 {
		t.Errorf("%d refusals reported a negative InUse; the refusal path subtracted a skewed pair and wrapped", n)
	}
	if n := refusals.Load(); n < minRefusals {
		t.Errorf("only %d refusals were collected, want at least %d; this test asserted almost nothing", n, minRefusals)
	}
	t.Logf("refusals=%d maxInUse=%d", refusals.Load(), maxInUse.Load())
}

// refusalRequestBytes is what the refusal benchmarks ask for: a
// credential-sized allocation, the shape [Allocator] is documented around. It
// is charged at page granularity, so the budget below refuses it.
const refusalRequestBytes = 32

// refusalBudgetBytes is the allocator budget the refusal benchmarks run
// against: one byte, which is below a single page and so admits nothing.
const refusalBudgetBytes = 1

// newRefusedAllocator returns an Allocator whose sub-page budget refuses every
// allocation through the ordinary `charge > free` predicate, before any locked
// memory is requested, so the benchmarks need no RLIMIT_MEMLOCK headroom and
// never write free. Before any timer starts it proves the refusal is a
// page-rounded BudgetError, since the benchmark loops only test err for nil.
func newRefusedAllocator(tb testing.TB) *budgetAllocator {
	tb.Helper()
	a, err := newBudgetAllocator(refusalBudgetBytes)
	if err != nil {
		tb.Fatalf("newBudgetAllocator(%d): %v", refusalBudgetBytes, err)
	}

	e, err := a.admitSized(refusalRequestBytes)
	if e != nil {
		// Nothing to measure if this admitted: destroy it so the probe does
		// not leak locked memory into the run it is validating.
		e.Destroy()
		tb.Fatalf("NewSized(%d) was ADMITTED against a %d-byte budget; the benchmark would time admission, not refusal",
			refusalRequestBytes, refusalBudgetBytes)
	}
	if !errors.Is(err, ErrBudgetExhausted) {
		tb.Fatalf("NewSized(%d) refused with %v, want ErrBudgetExhausted; the benchmark would time some other early return, not the budget branch",
			refusalRequestBytes, err)
	}
	var be *BudgetError
	if !errors.As(err, &be) {
		tb.Fatalf("refusal error is %T, want *BudgetError", err)
	}
	if want := LockedSize(refusalRequestBytes); be.Requested != want {
		tb.Fatalf("BudgetError.Requested = %d, want %d (the page-rounded charge)", be.Requested, want)
	}
	if be.Limit != refusalBudgetBytes {
		tb.Fatalf("BudgetError.Limit = %d, want %d", be.Limit, refusalBudgetBytes)
	}

	return a
}

// BenchmarkRefusalSerial and [BenchmarkRefusalParallel] guard the property that
// the refusal path is lock-free and scales: parallel refusal must cost no more
// per operation than serial. Compare the ratio, not nanoseconds; see
// docs/locked-memory-budget/engineering.md, Test strategy.
//
//	go test -run '^$' -bench 'Refusal' -benchtime 2s -count 8 . > new.txt
//	benchstat old.txt new.txt
func BenchmarkRefusalSerial(b *testing.B) {
	a := newRefusedAllocator(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := a.NewSized(refusalRequestBytes); err == nil {
			// The benchmark is measuring the wrong path entirely if this
			// fires, so it fails rather than reporting a fast admission.
			b.Fatal("NewSized was admitted; the benchmark is not measuring refusal")
		}
	}
}

// BenchmarkRefusalParallel refuses against one shared Allocator from
// GOMAXPROCS goroutines; the shared cacheline is what is under test. The loop
// writes no shared sink, which would add contention of its own.
func BenchmarkRefusalParallel(b *testing.B) {
	a := newRefusedAllocator(b)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := a.NewSized(refusalRequestBytes); err == nil {
				// b.Fatal is not usable from a RunParallel goroutine; Error
				// marks the benchmark failed, which is what a reader needs.
				b.Error("NewSized was admitted; the benchmark is not measuring refusal")
				return
			}
		}
	})
}

// TestAllocator_NilReceiver pins that a nil *budgetAllocator refuses with
// ErrNilAllocator from every method that can fail, wipes data New was handed,
// and reports zero from the observers.
func TestAllocator_NilReceiver(t *testing.T) {
	var a *budgetAllocator

	data := []byte("owned-by-new")
	if e, err := a.New(data); e != nil || !errors.Is(err, ErrNilAllocator) {
		t.Errorf("New = (%v, %v), want (nil, ErrNilAllocator)", e, err)
	}
	if !memscan.AllZero(data) {
		t.Error("New on a nil Allocator did not wipe the data it took ownership of")
	}
	if e, err := a.NewSized(32); e != nil || !errors.Is(err, ErrNilAllocator) {
		t.Errorf("NewSized = (%v, %v), want (nil, ErrNilAllocator)", e, err)
	}
	if err := a.SetLimit(pageSize); !errors.Is(err, ErrNilAllocator) {
		t.Errorf("SetLimit = %v, want ErrNilAllocator", err)
	}
	if excess, err := a.ForceLimit(pageSize); excess != 0 || !errors.Is(err, ErrNilAllocator) {
		t.Errorf("ForceLimit = (%d, %v), want (0, ErrNilAllocator)", excess, err)
	}
	dst, err := newBudgetAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := a.TransferTo(dst, pageSize); !errors.Is(err, ErrNilAllocator) {
		t.Errorf("TransferTo = %v, want ErrNilAllocator", err)
	}
	if dst.Limit() != pageSize {
		t.Errorf("destination Limit = %d after a refused transfer, want %d", dst.Limit(), pageSize)
	}
	if got := [3]int64{a.InUse(), a.Limit(), a.Available()}; got != [3]int64{} {
		t.Errorf("InUse, Limit, Available = %v, want zeros", got)
	}
}

// TestNewAllocator_ReturnsTheInterface pins that NewAllocator,
// NewAllocatorWithinRLimit and ProcessAllocator hand out the [Allocator]
// interface and New and NewSized a [ByteAccess], never a pointer a caller
// could hold as a concrete type; that every failure returns a nil interface;
// and that SetAllocator and TransferTo refuse an implementation this package
// did not build.
func TestNewAllocator_ReturnsTheInterface(t *testing.T) {
	a, err := NewAllocator(LockedSize(32))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if _, ok := a.(*budgetAllocator); !ok {
		t.Fatalf("NewAllocator returned a %T, want *budgetAllocator", a)
	}
	e, err := a.New([]byte("material"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := e.(*Memory); !ok {
		t.Errorf("New returned a %T, want *Memory", e)
	}
	if again, err := a.NewSized(32); again != nil || !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("NewSized past the budget = (%v, %v), want a nil interface and ErrBudgetExhausted", again, err)
	}
	if err := e.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	sized, err := a.NewSized(32)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}
	if _, ok := sized.(*Memory); !ok {
		t.Errorf("NewSized returned a %T, want *Memory", sized)
	}
	if err := sized.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	if got, err := NewAllocator(0); got != nil || !errors.Is(err, ErrInvalidBudget) {
		t.Errorf("NewAllocator(0) = (%v, %v), want a nil interface and ErrInvalidBudget", got, err)
	}
	if got, err := NewAllocatorWithinRLimit(0); got != nil || !errors.Is(err, ErrInvalidBudget) {
		t.Errorf("NewAllocatorWithinRLimit(0) = (%v, %v), want a nil interface and ErrInvalidBudget", got, err)
	}
	if p, err := ProcessAllocator(); err == nil {
		if _, ok := p.(*budgetAllocator); !ok {
			t.Errorf("ProcessAllocator returned a %T, want *budgetAllocator", p)
		}
	} else if p != nil {
		t.Errorf("ProcessAllocator = (%v, %v), want a nil interface with its error", p, err)
	}

	foreign := foreignAllocator{a}
	if err := SetAllocator(nil); !errors.Is(err, ErrNilAllocator) {
		t.Errorf("SetAllocator(nil) = %v, want ErrNilAllocator", err)
	}
	if err := SetAllocator(foreign); !errors.Is(err, ErrAllocatorNotConstructed) {
		t.Errorf("SetAllocator(foreign) = %v, want ErrAllocatorNotConstructed", err)
	}
	if err := a.TransferTo(nil, 1); !errors.Is(err, ErrInvalidTransfer) {
		t.Errorf("TransferTo(nil) = %v, want ErrInvalidTransfer", err)
	}
	if err := a.TransferTo(foreign, 1); !errors.Is(err, ErrAllocatorNotConstructed) {
		t.Errorf("TransferTo(foreign) = %v, want ErrAllocatorNotConstructed", err)
	}
	if a.Limit() != LockedSize(32) {
		t.Errorf("Limit = %d after refused transfers, want %d", a.Limit(), LockedSize(32))
	}
}

// foreignAllocator is an [Allocator] this package did not build. It forwards
// to a constructed one, so every method answers, but it is another type.
type foreignAllocator struct{ Allocator }

// freshProcessAllocator resets the one-shot process allocator so tests stay
// independent of order under -shuffle and -count>1.
func freshProcessAllocator(t *testing.T) {
	t.Helper()
	resetProcessAllocatorForTest()
	t.Cleanup(resetProcessAllocatorForTest)
}

// withDiscovery replaces the lazy default's ceiling discovery for one test.
func withDiscovery(t *testing.T, fn func() (LockedMemoryLimit, error)) {
	t.Helper()
	swapSeam(t, &discoverProcessLimit, fn)
}

func TestSetAllocator_InstalledAllocatorIsWhatLibrariesGet(t *testing.T) {
	freshProcessAllocator(t)

	a, err := newBudgetAllocator(4 * LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(a); err != nil {
		t.Fatalf("SetAllocator: %v", err)
	}

	got, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	if got != a {
		t.Fatal("ProcessAllocator returned a different allocator from the one installed")
	}
}

func TestSetAllocator_SecondInstallFailsClosed(t *testing.T) {
	freshProcessAllocator(t)

	first, err := newBudgetAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	second, err := newBudgetAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(first); err != nil {
		t.Fatalf("first SetAllocator: %v", err)
	}

	if err := SetAllocator(second); !errors.Is(err, ErrAllocatorInstalled) {
		t.Fatalf("second SetAllocator = %v, want ErrAllocatorInstalled", err)
	}
	// Failing closed means the FIRST one is still the answer, not merely that
	// an error was returned.
	got, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	if got != first {
		t.Fatal("a refused install replaced the installed allocator")
	}
}

func TestSetAllocator_NilIsRefusedAndLocksNothing(t *testing.T) {
	freshProcessAllocator(t)

	if err := SetAllocator(nil); !errors.Is(err, ErrNilAllocator) {
		t.Fatalf("SetAllocator(nil) = %v, want ErrNilAllocator", err)
	}

	// The refusal must not have consumed the one-shot: a real install after a
	// lost configuration step still succeeds.
	a, err := newBudgetAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(a); err != nil {
		t.Fatalf("SetAllocator after a nil refusal: %v", err)
	}
}

func TestProcessAllocator_LazyDefaultLocksTheConfiguration(t *testing.T) {
	freshProcessAllocator(t)
	withDiscovery(t, func() (LockedMemoryLimit, error) {
		return LockedMemoryLimit{Source: LimitUnlimited}, nil
	})

	def, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	again, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("second ProcessAllocator: %v", err)
	}
	if again != def {
		t.Fatal("the lazy default was installed twice")
	}

	late, err := newBudgetAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(late); !errors.Is(err, ErrAllocatorInstalled) {
		t.Fatalf("SetAllocator after a lazy default = %v, want ErrAllocatorInstalled", err)
	}
}

func TestProcessAllocator_DiscoveryFailureInstallsNothing(t *testing.T) {
	freshProcessAllocator(t)

	cause := errors.New("getrlimit refused")
	withDiscovery(t, func() (LockedMemoryLimit, error) {
		return LockedMemoryLimit{}, &LimitDiscoveryError{Cause: cause}
	})

	a, err := ProcessAllocator()
	if !errors.Is(err, ErrLimitDiscoveryFailed) || !errors.Is(err, cause) {
		t.Fatalf("ProcessAllocator = %v, want ErrLimitDiscoveryFailed wrapping the cause", err)
	}
	if a != nil {
		t.Fatal("a failed discovery returned an allocator")
	}

	// Nothing was installed, so the binary can still install its own; the
	// failure did not default to an unbounded allocator.
	mine, err := newBudgetAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(mine); err != nil {
		t.Fatalf("SetAllocator after a failed discovery: %v", err)
	}
}

func TestProcessAllocator_RetriesDiscoveryAfterAFailure(t *testing.T) {
	freshProcessAllocator(t)

	calls := 0
	withDiscovery(t, func() (LockedMemoryLimit, error) {
		calls++
		if calls == 1 {
			return LockedMemoryLimit{}, &LimitDiscoveryError{Cause: errors.New("transient")}
		}
		return LockedMemoryLimit{Bytes: 8 * LockedSize(1), Bounded: true, Source: LimitRLimit}, nil
	})

	if _, err := ProcessAllocator(); err == nil {
		t.Fatal("first ProcessAllocator succeeded; the injected failure was not reached")
	}
	a, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("second ProcessAllocator: %v", err)
	}
	if got, want := a.Limit(), 8*LockedSize(1); got != want {
		t.Fatalf("default budget = %d, want the discovered %d", got, want)
	}
}

func TestDefaultProcessAllocator_EveryCeilingShape(t *testing.T) {
	page := LockedSize(1)
	tests := []struct {
		name        string
		limit       LockedMemoryLimit
		wantBudget  int64
		wantSticky  bool
		admitsAPage bool
	}{
		{
			name:        "bounded ceiling becomes the budget, and sticks",
			limit:       LockedMemoryLimit{Bytes: 16 * page, Bounded: true, Source: LimitRLimit},
			wantBudget:  16 * page,
			wantSticky:  true,
			admitsAPage: true,
		},
		{
			name:        "a zero ceiling admits nothing",
			limit:       LockedMemoryLimit{Bytes: 0, Bounded: true, Source: LimitRLimit},
			wantBudget:  0,
			wantSticky:  true,
			admitsAPage: false,
		},
		{
			name:        "RLIM_INFINITY has no figure to admit against",
			limit:       LockedMemoryLimit{Source: LimitUnlimited},
			wantBudget:  math.MaxInt64,
			admitsAPage: true,
		},
		{
			name:        "an unenforced limit is a diagnostic, not a ceiling",
			limit:       LockedMemoryLimit{Bytes: page, Source: LimitNotEnforced},
			wantBudget:  math.MaxInt64,
			admitsAPage: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := defaultProcessAllocator(tt.limit)
			if got := a.Limit(); got != tt.wantBudget {
				t.Fatalf("budget = %d, want %d", got, tt.wantBudget)
			}
			if a.rlimitBound != tt.wantSticky {
				t.Fatalf("rlimitBound = %v, want %v", a.rlimitBound, tt.wantSticky)
			}
			if a.InUse() != 0 {
				t.Fatalf("a fresh default reports %d bytes in use", a.InUse())
			}

			e, err := a.admitSized(1)
			if !tt.admitsAPage {
				if !errors.Is(err, ErrBudgetExhausted) {
					t.Fatalf("NewSized on a zero budget = %v, want ErrBudgetExhausted", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewSized: %v", err)
			}
			e.Destroy()
			if a.InUse() != 0 {
				t.Fatalf("Destroy left %d bytes charged to the default", a.InUse())
			}
		})
	}
}

// TestProcessAllocator_DefaultMatchesThisHost checks the real discovery path,
// unseamed, on whatever ceiling the test host has: the default's budget is the
// discovered figure when it binds and unbounded when it does not.
func TestProcessAllocator_DefaultMatchesThisHost(t *testing.T) {
	freshProcessAllocator(t)

	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	a, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}

	want := int64(math.MaxInt64)
	if limit.Bounded {
		want = limit.Bytes
	}
	if got := a.Limit(); got != want {
		t.Fatalf("default budget = %d, want %d (discovered %+v)", got, want, limit)
	}
	t.Logf("host ceiling %+v -> default budget %d", limit, a.Limit())
}

// TestProcessAllocator_ConcurrentFirstUseInstallsOne races the lazy default:
// every caller must see the same allocator.
func TestProcessAllocator_ConcurrentFirstUseInstallsOne(t *testing.T) {
	freshProcessAllocator(t)
	withDiscovery(t, func() (LockedMemoryLimit, error) {
		return LockedMemoryLimit{Source: LimitUnlimited}, nil
	})

	const callers = 32
	got := make([]Allocator, callers)
	errs := make([]error, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			got[i], errs[i] = ProcessAllocator()
		}()
	}
	close(start)

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent ProcessAllocator calls did not return; the install lock is stuck")
	}

	for i := range callers {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if got[i] != got[0] {
			t.Fatalf("caller %d got a different allocator; the default was installed more than once", i)
		}
	}
}

// TestProcessAllocator_OneBudgetAcrossCallers pins that two independent callers
// share one budget: the second is refused with the typed error before any
// locked memory is requested, and a release returns the room.
func TestProcessAllocator_OneBudgetAcrossCallers(t *testing.T) {
	freshProcessAllocator(t)

	a, err := newBudgetAllocator(LockedSize(1))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if err := SetAllocator(a); err != nil {
		t.Fatalf("SetAllocator: %v", err)
	}

	libraryA, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	held, err := libraryA.NewSized(32)
	if err != nil {
		t.Fatalf("first admission: %v", err)
	}

	libraryB, err := ProcessAllocator()
	if err != nil {
		t.Fatalf("ProcessAllocator: %v", err)
	}
	_, err = libraryB.NewSized(32)
	var be *BudgetError
	if !errors.Is(err, ErrBudgetExhausted) || !errors.As(err, &be) {
		t.Fatalf("second library's admission = %v, want a BudgetError matching ErrBudgetExhausted", err)
	}

	held.Destroy()
	again, err := libraryB.NewSized(32)
	if err != nil {
		t.Fatalf("admission after the first holder released: %v", err)
	}
	again.Destroy()
}

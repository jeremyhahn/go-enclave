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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestNewAllocator_InvalidBudget(t *testing.T) {
	for _, n := range []int64{0, -1, -4096} {
		a, err := NewAllocator(n)
		if !errors.Is(err, ErrInvalidBudget) {
			t.Errorf("NewAllocator(%d) err = %v, want ErrInvalidBudget", n, err)
		}
		if a != nil {
			t.Errorf("NewAllocator(%d) returned a non-nil allocator on error", n)
		}
	}
	a, err := NewAllocator(4096)
	if err != nil {
		t.Fatalf("NewAllocator(4096): %v", err)
	}
	if a.Limit() != 4096 {
		t.Errorf("Limit = %d, want 4096", a.Limit())
	}
	if a.InUse() != 0 || a.Available() != 4096 {
		t.Errorf("fresh allocator InUse=%d Available=%d, want 0 and 4096", a.InUse(), a.Available())
	}
}

func TestAllocator_New_Admits(t *testing.T) {
	limit := 4 * pageSize
	a, err := NewAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	material := []byte("admitted-key-material")

	e, err := a.New(material)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Destroy()

	// Charged a whole page, not the 21 bytes of material: that is what the
	// kernel locks, and the budget is denominated in what the kernel charges.
	if a.InUse() != pageSize {
		t.Errorf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
	if a.Available() != limit-pageSize {
		t.Errorf("Available = %d, want %d", a.Available(), limit-pageSize)
	}
	if got, err := e.OpenString(); err != nil || got != "admitted-key-material" {
		t.Errorf("OpenString = %q, %v; want the material", got, err)
	}
}

// TestAllocator_New_RefusesOverBudget asserts admission actually gates: an
// allocation that would exceed the budget is refused with ErrBudgetExhausted,
// no enclave is returned, and the budget is left exactly as it was. Deleting
// the over-budget refusal (or weakening the `>` comparison) lets the second
// New through and fails this test.
func TestAllocator_New_RefusesOverBudget(t *testing.T) {
	// One page of budget holds exactly one enclave, however small its material.
	a, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	first, err := a.New(bytes.Repeat([]byte("x"), 24))
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	defer first.Destroy()

	before := a.InUse()
	e, err := a.New(bytes.Repeat([]byte("y"), 16))
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
	// The figures are in locked bytes throughout — 16 bytes of material costs
	// a page, and the page already taken is what leaves no room.
	if be.Requested != pageSize || be.Limit != pageSize || be.InUse != pageSize {
		t.Errorf("BudgetError = %+v, want Requested=InUse=Limit=%d", be, pageSize)
	}
}

// TestAllocator_New_WipesSourceOnRefusal asserts the ownership contract holds
// on the refusal path: a refused allocation still wipes the caller's slice, so
// no unprotected copy of the material survives a denied admission. Deleting the
// Wipe(data) call on the refusal path fails this test.
func TestAllocator_New_WipesSourceOnRefusal(t *testing.T) {
	a, err := NewAllocator(8)
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

// TestAllocator_Destroy_ReleasesReservation is the release-path mutation
// killer. A budget-releasing Destroy is invisible to any behavioral check on
// the enclave itself — the material reads back identically whether or not the
// reservation is returned — so the property is asserted on the ALLOCATOR: fill
// the budget, confirm the next allocation is refused, destroy the holder, and
// confirm an identical allocation now succeeds. Deleting `e.release = …` in
// Allocator.New, or the releaseOnce.Do(e.release) in Destroy, leaves the
// budget consumed forever and fails the final New.
func TestAllocator_Destroy_ReleasesReservation(t *testing.T) {
	a, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := a.New(bytes.Repeat([]byte("a"), 16))
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
	e2, err := a.New(bytes.Repeat([]byte("c"), 16))
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
	a, err := NewAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.New(bytes.Repeat([]byte("z"), 32))
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
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	for name, in := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			e, err := a.New(in)
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

func TestBudgetError(t *testing.T) {
	t.Run("matches the sentinel", func(t *testing.T) {
		err := error(&BudgetError{Requested: 10, InUse: 20, Limit: 25})
		if !errors.Is(err, ErrBudgetExhausted) {
			t.Error("errors.Is did not match ErrBudgetExhausted")
		}
	})
	t.Run("does not match unrelated sentinels", func(t *testing.T) {
		err := error(&BudgetError{})
		if errors.Is(err, ErrLockedMemoryUnavailable) || errors.Is(err, ErrEnclaveDestroyed) {
			t.Error("BudgetError matched an unrelated sentinel")
		}
	})
	t.Run("message carries the figures", func(t *testing.T) {
		err := error(&BudgetError{Requested: 10, InUse: 20, Limit: 25})
		msg := err.Error()
		for _, want := range []string{"10", "20", "25", "budget exhausted"} {
			if !strings.Contains(msg, want) {
				t.Errorf("Error() = %q, want it to contain %q", msg, want)
			}
		}
	})
}

// TestAllocator_Concurrent runs many concurrent New/Destroy cycles against a
// tight budget. The invariant under -race: InUse never exceeds the limit at
// any observed point (the CAS refuses rather than overshooting), and the
// counter returns to exactly zero once every enclave is destroyed.
func TestAllocator_Concurrent(t *testing.T) {
	// Budget in PAGES: each enclave costs one whatever its material's size, so
	// a budget expressed in the material's bytes would refuse every single
	// allocation and leave this test asserting nothing. That is exactly what it
	// did when the accounting changed, silently and while still green — hence
	// the admitted counter below.
	const capacity = 5
	limit := capacity * pageSize
	a, err := NewAllocator(limit)
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
				e, err := a.New(bytes.Repeat([]byte("k"), 40))
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

// TestAllocator_New_KeepsTheChargeForPagesACleanupCouldNotRelease is the
// regression for the constructor-refund finding in #83.
//
// Allocator.New maps and locks, then freezes; when the freeze is refused it
// releases the mapping, and when THAT is refused too — the wipe-enabling
// mprotect and the unmap fallback both denied — the locked pages stay
// behind with no handle. New refunded the whole charge anyway, so the budget
// advertised locked memory the process could not use: the stance Destroy
// refuses to take for exactly the same pages.
//
// The control is the same refusal with the fallback ALLOWED: the pages go back
// and the charge must too, so a fix that simply stopped refunding fails here.
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
			a, err := NewAllocator(4 * pageSize)
			if err != nil {
				t.Fatalf("NewAllocator: %v", err)
			}

			denied := errors.New("mprotect denied by policy")
			prevProtect, prevUnmap := protectMemory, unmapMemory
			// Stranded pages are on the orphan ledger, so they are reclaimed the
			// way production reclaims them — by a sweep once the refusal lifts —
			// and never freed behind the ledger's back, which would leave it a
			// record of an unmapped region.
			t.Cleanup(func() {
				protectMemory, unmapMemory = prevProtect, prevUnmap
				_, _ = WipeAll(context.Background())
			})
			protectMemory = func([]byte, protection) error { return denied }
			unmapMemory = func(b []byte) error {
				if tc.bypassOK {
					return prevUnmap(b)
				}
				return errors.New("munmap denied too")
			}

			e, err := a.New(material())
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

// TestAllocator_New_RefundsWhenTheCleanupUnlockedButCouldNotUnmap pins the
// other half of the refund predicate (#83): a failed construction whose cleanup
// UNLOCKED the pages and was then refused the munmap leaves them mapped but no
// longer locked. That costs address space and no locked memory, and the failed
// constructor hands back no enclave to retry through, so keeping the charge
// would shrink the budget for the process lifetime with nothing locked behind
// it. A first cut of the fix keyed the refund on "pages held" alone and did
// exactly that (caught by Codex reviewing the #83 branch).
func TestAllocator_New_RefundsWhenTheCleanupUnlockedButCouldNotUnmap(t *testing.T) {
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	prevProtect, prevUnmap := protectMemory, unmapMemory
	var stranded bool
	// Reclaimed through the orphan ledger, never freed behind its back; see
	// TestAllocator_New_KeepsTheChargeForPagesACleanupCouldNotRelease.
	t.Cleanup(func() {
		protectMemory, unmapMemory = prevProtect, prevUnmap
		_, _ = WipeAll(context.Background())
	})
	// Only the freeze (read-only) is refused, so construction fails and the
	// cleanup wipes, unlocks, and is refused the unmap.
	protectMemory = func(b []byte, p protection) error {
		if p == protReadOnly {
			return errors.New("mprotect denied by policy")
		}
		return prevProtect(b, p)
	}
	unmapMemory = func([]byte) error {
		stranded = true
		return errors.New("munmap: cannot allocate memory")
	}

	e, err := a.New(material())
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

// TestAllocator_NewSized_RefundsWhenALockFailureLeavesNothingLocked is the
// control for the predicate on the NewSized path: an mlock refused at the
// ceiling leaves nothing locked and the rollback's munmap returns the mapping,
// so the charge goes back and the failure is not marked as holding pages. The
// arm where that munmap is refused as well is
// TestAllocator_NewSized_UnlockedOrphanIsReclaimedWithoutASecondRefund.
func TestAllocator_NewSized_RefundsWhenALockFailureLeavesNothingLocked(t *testing.T) {
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	prevLock, prevUnmap := lockMemory, unmapMemory
	t.Cleanup(func() { lockMemory, unmapMemory = prevLock, prevUnmap })
	lockMemory = func([]byte) error { return errors.New("mlock: cannot allocate memory") }
	unmaps := 0
	unmapMemory = func(b []byte) error {
		unmaps++
		return prevUnmap(b)
	}

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

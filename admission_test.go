// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-enclave.
//
// go-enclave is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package enclave

import (
	"bytes"
	"errors"
	"strings"
	"sync"
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
	a, err := NewAllocator(1024)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	material := []byte("admitted-key-material")
	want := len(material)

	e, err := a.New(material)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Destroy()

	if a.InUse() != int64(want) {
		t.Errorf("InUse = %d, want %d", a.InUse(), want)
	}
	if a.Available() != 1024-int64(want) {
		t.Errorf("Available = %d, want %d", a.Available(), 1024-int64(want))
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
	a, err := NewAllocator(32)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	first, err := a.New(bytes.Repeat([]byte("x"), 24))
	if err != nil {
		t.Fatalf("first New: %v", err)
	}
	defer first.Destroy()

	before := a.InUse()
	e, err := a.New(bytes.Repeat([]byte("y"), 16)) // 24 + 16 = 40 > 32
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
	if be.Requested != 16 || be.Limit != 32 || be.InUse != 24 {
		t.Errorf("BudgetError = %+v, want Requested=16 InUse=24 Limit=32", be)
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
	a, err := NewAllocator(16)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := a.New(bytes.Repeat([]byte("a"), 16))
	if err != nil {
		t.Fatalf("New (full): %v", err)
	}
	if a.InUse() != 16 {
		t.Fatalf("InUse = %d, want 16", a.InUse())
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
	a, err := NewAllocator(64)
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
	if a.Available() != 64 {
		t.Fatalf("Available = %d after double Destroy, want the full 64", a.Available())
	}
}

func TestAllocator_New_Empty(t *testing.T) {
	a, err := NewAllocator(1024)
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
	const limit = 200
	a, err := NewAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

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
				if u := a.InUse(); u > limit {
					t.Errorf("InUse = %d exceeded limit %d", u, limit)
				}
				e.Destroy()
			}
		}()
	}
	wg.Wait()

	if a.InUse() != 0 {
		t.Errorf("InUse = %d after all destroys, want 0", a.InUse())
	}
	if a.Available() != limit {
		t.Errorf("Available = %d, want the full %d", a.Available(), limit)
	}
}

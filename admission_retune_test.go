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
	"errors"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// material returns a non-empty slice for New to take ownership of. Every enclave
// costs one whole page whatever this returns, which is the accounting the budget
// is denominated in.
func material() []byte { return bytes.Repeat([]byte("k"), 40) }

// waitBounded joins wg or fails the test. Every wait in this file is bounded on
// purpose: the regressions these tests guard — a lock-order inversion, a
// non-reentrant lock taken twice — present as a hang, and an unbounded wait
// turns a named failure into an unexplained suite timeout.
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

// TestAllocator_SetLimit_RaiseAdmitsWhatWasRefused is the issue's headline
// verification: a budget raised at runtime admits an allocation that was
// refused before it. The refusal before the raise is what makes the success
// after it mean something — without it the final New would pass on an allocator
// that had room all along.
func TestAllocator_SetLimit_RaiseAdmitsWhatWasRefused(t *testing.T) {
	a, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	first, err := a.New(material())
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

	second, err := a.NewSized(32)
	if err != nil {
		t.Fatalf("NewSized after the raise: %v (the new headroom was not admissible)", err)
	}
	second.Destroy()
}

// TestAllocator_SetLimit_RefusesBelowInUse names the contract for the hard case
// — lowering under live reservations — and proves the refusal changes nothing.
// The control at the end is the other half of the claim: a lowering that DOES
// fit must succeed, or "refuses below in use" would be indistinguishable from
// "refuses every lowering".
func TestAllocator_SetLimit_RefusesBelowInUse(t *testing.T) {
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.New([]byte("retune-material"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer e.Destroy()

	err = a.SetLimit(pageSize / 2)
	if !errors.Is(err, ErrBudgetInUse) {
		t.Fatalf("SetLimit below in-use = %v, want ErrBudgetInUse", err)
	}
	var le *LimitError
	if !errors.As(err, &le) {
		t.Fatalf("err is not a *LimitError: %v", err)
	}
	if le.Requested != pageSize/2 || le.InUse != pageSize || le.Limit != 4*pageSize {
		t.Errorf("LimitError = %+v, want Requested=%d InUse=%d Limit=%d",
			le, pageSize/2, pageSize, 4*pageSize)
	}

	// Nothing moved: budget, usage and headroom are exactly as they were.
	if a.Limit() != 4*pageSize || a.InUse() != pageSize || a.Available() != 3*pageSize {
		t.Errorf("after refusal Limit=%d InUse=%d Available=%d, want %d, %d, %d",
			a.Limit(), a.InUse(), a.Available(), 4*pageSize, pageSize, 3*pageSize)
	}
	// And the enclave was not silently invalidated by a budget decision.
	if got, err := e.OpenString(); err != nil || got != "retune-material" {
		t.Errorf("OpenString after refused lowering = %q, %v; want the material intact", got, err)
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
		a, err := NewAllocator(2 * pageSize)
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
		if _, err := NewAllocator(0); !errors.Is(err, ErrInvalidBudget) {
			t.Fatalf("NewAllocator(0) = %v, want ErrInvalidBudget", err)
		}
		a, err := NewAllocator(pageSize)
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
		e, err := a.NewSized(32)
		if err != nil {
			t.Fatalf("NewSized after unquiescing: %v", err)
		}
		e.Destroy()
	})

	t.Run("setting the same budget is a no-op", func(t *testing.T) {
		a, err := NewAllocator(2 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		e, err := a.New(material())
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

// TestAllocator_ForceLimit_LowersBeneathLiveReservations names the other
// contract: the ceiling MOVED, so the budget is recorded even though the
// reservations no longer fit. The properties that make it safe are that the
// caller is told the excess, live enclaves keep working, and nothing further is
// admitted until they drain.
func TestAllocator_ForceLimit_LowersBeneathLiveReservations(t *testing.T) {
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e1, err := a.New([]byte("first-secret"))
	if err != nil {
		t.Fatalf("New(e1): %v", err)
	}
	e2, err := a.New([]byte("second-secret"))
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
	if got, err := e1.OpenString(); err != nil || got != "first-secret" {
		t.Errorf("e1.OpenString = %q, %v; want the material intact", got, err)
	}
	if got, err := e2.OpenString(); err != nil || got != "second-secret" {
		t.Errorf("e2.OpenString = %q, %v; want the material intact", got, err)
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
	e3, err := a.NewSized(32)
	if err != nil {
		t.Fatalf("NewSized after the drain: %v", err)
	}
	e3.Destroy()
}

func TestAllocator_ForceLimit_Bounds(t *testing.T) {
	t.Run("a lowering that fits reports no excess", func(t *testing.T) {
		a, err := NewAllocator(4 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		e, err := a.New(material())
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
		a, err := NewAllocator(pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		e, err := a.New(material())
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
		second, err := a.NewSized(32)
		if err != nil {
			t.Fatalf("NewSized after ForceLimit raise: %v", err)
		}
		second.Destroy()
	})

	t.Run("the same budget reports the standing excess", func(t *testing.T) {
		a, err := NewAllocator(2 * pageSize)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		e, err := a.New(material())
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
		a, err := NewAllocator(2 * pageSize)
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

// TestAllocator_TransferTo_MovesHeadroom proves the transfer does what it is
// for: the receiving allocator admits an allocation it refused a moment before,
// the giving allocator gives up exactly that much, and the total across the pair
// is conserved.
//
// It runs both construction orders on purpose. TransferTo acquires the two
// locks by ascending construction id, so donating to a younger allocator takes
// the ordering branch straight through and donating to an older one takes the
// swap; the observable behavior must be identical either way.
func TestAllocator_TransferTo_MovesHeadroom(t *testing.T) {
	for _, srcFirst := range []bool{true, false} {
		name := "source constructed first"
		if !srcFirst {
			name = "destination constructed first (lock order swaps)"
		}
		t.Run(name, func(t *testing.T) {
			var src, dst *Allocator
			mk := func(n int64) *Allocator {
				t.Helper()
				a, err := NewAllocator(n)
				if err != nil {
					t.Fatalf("NewAllocator(%d): %v", n, err)
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

			hold, err := dst.New(material())
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

			e, err := dst.NewSized(32)
			if err != nil {
				t.Fatalf("dst.NewSized after the transfer: %v (the moved headroom was not admissible)", err)
			}
			e.Destroy()
		})
	}
}

// TestAllocator_TransferTo_RefusedWithoutHeadroom asserts a source cannot donate
// headroom it does not have — that would be the over-commit in a different
// costume — and that the refusal leaves BOTH allocators untouched. The control
// destroys one enclave and shows the same transfer then succeeds.
func TestAllocator_TransferTo_RefusedWithoutHeadroom(t *testing.T) {
	src, err := NewAllocator(2 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	dst, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e1, err := src.New(material())
	if err != nil {
		t.Fatalf("New(e1): %v", err)
	}
	e2, err := src.New(material())
	if err != nil {
		t.Fatalf("New(e2): %v", err)
	}
	defer e2.Destroy()

	err = src.TransferTo(dst, pageSize)
	if !errors.Is(err, ErrBudgetInUse) {
		t.Fatalf("TransferTo without headroom = %v, want ErrBudgetInUse", err)
	}
	var le *LimitError
	if !errors.As(err, &le) {
		t.Fatalf("err is not a *LimitError: %v", err)
	}
	// Requested is the budget the SOURCE would have been left with.
	if le.Requested != pageSize || le.InUse != 2*pageSize || le.Limit != 2*pageSize {
		t.Errorf("LimitError = %+v, want Requested=%d InUse=%d Limit=%d",
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
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	b, err := NewAllocator(4 * pageSize)
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

// TestAllocator_TransferTo_DestinationOverflow covers the arithmetic edge the
// destination check exists for. It is unreachable with any real locked-memory
// budget — it needs 8 EiB — but the check is what keeps the credit from wrapping
// the destination's budget negative, which would turn a rebalance into an
// allocator that admits nothing forever.
func TestAllocator_TransferTo_DestinationOverflow(t *testing.T) {
	src, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	dst, err := NewAllocator(math.MaxInt64)
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

// TestAllocator_TransferTo_NeverInBoth is the witness for the direction of the
// transfer's intermediate state. Two independent counters cannot be updated by
// one instruction, so a transfer necessarily passes through a state where the
// moved bytes are in only one place; the whole safety argument rests on that
// place being NEITHER allocator rather than both. "Both" would let each side
// admit against the same locked bytes for the length of the window, which is the
// over-commit this type exists to prevent.
//
// The sampler reads the DESTINATION's counter first and the source's second,
// which is the opposite order to the writes, and that ordering is what makes the
// check sound rather than flaky. With the correct write order — debit the source,
// then credit the destination — a sample that sees the credit must have been
// taken after the debit, so it sees that too and the sum is exactly the total; a
// sample that misses the credit sums to the total or one transfer less. The sum
// can therefore never exceed the total. Reverse the two writes and the sampler
// can see a credited destination beside an undebited source, which is the excess
// this fails on.
//
// Transfers run in one direction only, for the same reason: the read order that
// makes the sampler sound is chosen against a known write order, and a returning
// transfer would write the two counters the other way round and manufacture the
// very reading it is looking for.
func TestAllocator_TransferTo_NeverInBoth(t *testing.T) {
	const moves = 4000
	src, err := NewAllocator(moves * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	dst, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	total := src.Limit() + dst.Limit()

	var samples, violations atomic.Int64
	// Each side has a FLOOR of its own that no scheduling order can cut short,
	// and the sampler additionally outlives the transfers. Sizing it as "sampler
	// runs until the transfers stop" is what failed here: under GOMAXPROCS=1 the
	// transfer goroutine ran all 4000 transfers and closed the stop channel
	// before the sampler was ever scheduled, and the run reported
	// `samples=0` — green, having looked at nothing.
	const minSamples = 1000
	transfersDone := make(chan struct{})
	samplerReady := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			// The floor comes first: only once minSamples are in the bag does
			// the sampler start looking for a reason to stop.
			if i >= minSamples {
				select {
				case <-transfersDone:
					return
				default:
				}
			}
			// Destination first, source second — see the doc comment. This
			// ordering is the reason the check has no false positives.
			d := dst.free.Load()
			s := src.free.Load()
			if samples.Add(1) == 1 {
				// The transfers wait for this, so they cannot run to completion
				// before the sampler exists.
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

func TestLimitError(t *testing.T) {
	t.Run("matches the sentinel", func(t *testing.T) {
		err := error(&LimitError{Requested: 10, InUse: 20, Limit: 25})
		if !errors.Is(err, ErrBudgetInUse) {
			t.Error("errors.Is did not match ErrBudgetInUse")
		}
	})
	t.Run("does not match unrelated sentinels", func(t *testing.T) {
		err := error(&LimitError{})
		if errors.Is(err, ErrBudgetExhausted) || errors.Is(err, ErrInvalidBudget) ||
			errors.Is(err, ErrInvalidTransfer) || errors.Is(err, ErrLockedMemoryUnavailable) {
			t.Error("LimitError matched an unrelated sentinel")
		}
	})
	t.Run("message carries the figures", func(t *testing.T) {
		err := error(&LimitError{Requested: 10, InUse: 20, Limit: 25})
		msg := err.Error()
		for _, want := range []string{"10", "20", "25", "already reserved"} {
			if !strings.Contains(msg, want) {
				t.Errorf("Error() = %q, want it to contain %q", msg, want)
			}
		}
	})
}

// TestAllocator_StaysWithinItsCachelineBudget guards the budget that
// [Allocator.stalled] spent the last of.
//
// 64 is a FIXED BUDGET here, not a discovered line size, and the difference is
// worth stating because this test's first name claimed the latter. It is the
// line size on the platforms this package builds and ships on, and Go gives a
// portable program no way to ask the machine. On a target with larger lines the
// assertion is merely conservative; on one with 32-byte lines it would pass
// while the property it was first named for fails. What it catches on EVERY
// target is the regression it exists for — a field appended to the hot type,
// doubling its footprint — so the budget is deliberately a constant rather than
// a build-tag matrix. For reference, the type is 64 bytes on amd64 and 56 on
// 386.
//
// This type's design is cacheline behavior on two atomic words: admission reads
// free on every allocation and refusals read limit beside it, and the whole
// lock-free argument assumes those two are not sharing a line with something
// being written by an unrelated goroutine. Nothing enforced that.
//
// It became worth enforcing because the slack ran out invisibly, in a way
// neither change could see alone. The seam field cost 8 bytes and #53's
// rlimitBound cost 1 — but rlimitBound lands at offset 48, a func pointer needs
// 8-byte alignment, so the bool drags 7 bytes of padding and the pair takes the
// struct from 56 bytes to exactly 64. Each diff looked free in isolation; the
// bill only existed in the combined struct, which came into being at a rebase,
// so no reviewer of either pull request could have been shown it.
//
// 64 is the whole line. The NEXT field of any size at all pushes this type into
// a second cacheline and puts the hot pair at risk of sharing one, and there is
// no reason a reviewer would notice — which is what this test is for. If it
// fails, the question is not how to make the number fit; it is whether the new
// field belongs on the hot type at all, and if it does, whether free and limit
// should be moved into their own aligned struct.
func TestAllocator_StaysWithinItsCachelineBudget(t *testing.T) {
	const line = 64

	got := unsafe.Sizeof(Allocator{})
	if got > line {
		t.Errorf("Allocator is %d bytes, over the %d-byte cacheline budget: the field just added pushed the type into a second line — see this test's comment before widening the budget",
			got, line)
	}
	// The two words admission actually touches must stay in the same line as
	// each other, which is a stronger statement than the size and is the one
	// the lock-free paths depend on.
	free, limit := unsafe.Offsetof(Allocator{}.free), unsafe.Offsetof(Allocator{}.limit)
	if free/line != limit/line {
		t.Errorf("free is at offset %d and limit at %d, in different %d-byte lines: the two words admission and refusal read together are now split",
			free, limit, line)
	}
	t.Logf("Allocator size=%d budget=%d free@%d limit@%d", got, line, free, limit)
}

// retuneActors is the number of goroutines that contend for pages in each round
// of [TestAllocator_Retune_RacesAdmission], besides the one retuner. Each of
// them either takes exactly one page or gives exactly one back, and every
// round's arithmetic is written in terms of this count.
//
// What bounds it is the process's RLIMIT_MEMLOCK, and the mechanism is worth
// stating because the plausible guess is the wrong one. These rounds build
// their allocators with [NewAllocator], so rlimitBound is false, ceilingForRaise
// returns the unbounded zero value and the ceiling contract added in #53 cannot
// refuse anything here — measured: the whole file passes under `ulimit -l 32`,
// below the 36 KiB the raise nominally asks for. The real wall is the kernel
// refusing the mlock, and the pressure is retuneActors pages rather than one
// more: the retuner moves BUDGET, and a budget page is not an mlock'd page.
// Only live enclaves are locked, and every shape holds at most retuneActors of
// them, admitted plus pre-held. Measured on both sides of that — `ulimit -l 32`,
// eight pages, exactly retuneActors, passes the whole file; `ulimit -l 16` fails
// every round with ErrLockedMemoryUnavailable, reported as "unexpected NewSized
// err" rather than as anything naming a ceiling. Scale the cast and that is the
// limit to check, and that is the error to expect.
const retuneActors = 8

// retuneShape describes one kind of arranged round: the budget it opens on, how
// many actors reach for a page, and how many hand one back while the retuner is
// deciding.
//
// Sizes are in PAGES because every claim in a round is exactly one page: an
// admission of 32 bytes charges lockedSize(32), which is one page, and the
// retuner withdraws one page. That is what makes a round's outcome arithmetic
// rather than a prediction — see [TestAllocator_Retune_RacesAdmission].
type retuneShape struct {
	name string
	// limit is the budget the round's allocator is constructed with. The
	// retuner raises it by one page at the head of the round, before the
	// contest opens, and that page is the one being contested.
	limit int64
	// admit is how many actors attempt exactly one admission each.
	admit int
	// drain is how many actors destroy one pre-held enclave each, returning a
	// page to the budget while the lowering is deciding.
	drain int
}

// supply is the page claims available to the round: the budget, plus the page
// the retuner's raise puts into circulation, less the pages the pre-held
// enclaves are sitting on when the round opens.
//
// Pages returned by the draining actors are deliberately NOT counted. A claim
// that is only affordable because a concurrent Destroy has already landed is a
// claim that depends on the scheduler, which is the property this test was
// rewritten to stop depending on; the shapes are chosen so no claim does.
func (sh retuneShape) supply() int64 { return sh.limit + 1 - int64(sh.drain) }

// demand is the page claims attempted: one per admitting actor, plus the
// retuner's withdrawal.
func (sh retuneShape) demand() int64 { return int64(sh.admit) + 1 }

// granted is how many of those claims MUST succeed, on every host and every
// interleaving. It is the smaller of supply and demand, and both halves of that
// are load-bearing:
//
//   - No more, because a page cannot be granted twice. Two claims sharing one
//     page is the over-commit this whole type exists to prevent, and it is what
//     an over-subscribed round is arranged to detect.
//   - No fewer, because no contender gives up while a page is free: an
//     admission is refused only when it reads the counter at exactly zero (the
//     charge is one page and the counter moves in whole pages), and the same
//     holds for the withdrawal. Nothing puts a page back afterwards either —
//     the raise is done before the line, and a shape that is short of supply
//     is not allowed to drain, which runRetuneShape enforces.
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
	a     *Allocator
	held  []*MemoryEnclave // one per draining actor; destroyed inside the window
	got   []*MemoryEnclave // one per admitting actor; nil where it was refused

	wg      sync.WaitGroup
	arrived atomic.Int32

	admitted atomic.Int64
	refused  atomic.Int64
	lowered  atomic.Bool
}

// line parks the caller until every participant in the round has reached it, so
// the claims that follow are made against each other rather than in whatever
// order the goroutines happened to start.
//
// It is bounded and it FAILS on the bound rather than returning quietly. A
// harness whose synchronization has broken does not produce a weaker test, it
// produces a test measuring something else entirely — so a participant that
// never arrives has to say so in those words, not leave the round looking like
// a legitimate result.
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

// retuneTally is the run-wide count of what the arranged rounds actually did.
// The controls at the end of [TestAllocator_Retune_RacesAdmission] read it, and
// it is what the test logs: the counts are the evidence that the path ran.
type retuneTally struct {
	admitted     atomic.Int64
	refusedAdmit atomic.Int64
	raised       atomic.Int64
	lowered      atomic.Int64
	refusedLower atomic.Int64
	overCommit   atomic.Int64
}

// TestAllocator_Retune_RacesAdmission is the test the retune design exists to
// pass: a budget lowering and an admission decide against the same free bytes,
// and the compare-and-swap they share must linearize them so that exactly one
// of them gets a contested page. Both getting it means the process has promised
// locked memory the kernel will not hand over, and the failure surfaces later,
// somewhere else, as ErrLockedMemoryUnavailable.
//
// # The contest is ARRANGED, and the two earlier versions are why
//
// Both earlier versions ran a storm — goroutines allocating and destroying in a
// tight loop against goroutines raising a page and taking it back — and read
// the outcome off the counters afterwards. Both were measured executing
// nothing:
//
//   - A ONE-page budget starved the allocators: twelve admissions against
//     twenty-four hundred refusals, in a test about what happens when an
//     admission commits.
//   - Retuners withdrawing a page from a two-page budget starved the other way.
//     Under GOMAXPROCS=1 every one of 2400 lowerings was refused, and the run
//     reported green on a retune path it had never once executed.
//
// The second measurement is what the vacuity controls at the bottom of this
// test were added for, and they did their job: they fired on a saturated CI
// runner with `raised=2400 lowered=0`, failing an unrelated pull request
// (issue #51). Raising a page and lowering it back had made that starvation
// rarer, not impossible.
//
// The mechanism is not subtle. Goroutines allocating in a loop hold the free
// counter at zero, so the page a retuner puts into circulation is taken by an
// admission before that same retuner reaches its own withdrawal a few
// instructions later — and a couple of allocator goroutines descheduled while
// each holds a page keep the counter at zero for as long as they stay off the
// CPU. Whether the shrinking path runs at all is therefore decided by the
// scheduler. Measured on the storm version at f718f10, one 8-core host, no
// change to the code under test: idle `lowered=43` of 2400; the same binary
// under CPU load `lowered=2400` of 2400; GOMAXPROCS=1 and `taskset -c 0` a flat
// `admitted=600 refusedAdmit=1800 lowered=2400` on every run, which is not a
// race at all but sixteen goroutines run to completion in turn. A fifty-fold
// swing in how much of the path ran, none of it under the test's control.
//
// # Occupancy, which is the axis the earlier repairs missed
//
// The author of the storm fixed two starvations here before this one, and the
// rule it took from them was about TRUNCATION: whichever side can be cut short
// by a scheduling order is the side that reports green having done nothing, so
// let the side you assert about bound the run. That rule is right and it does
// not cover this failure. Nothing was truncated in the CI run — raised=2400 says
// the retuner ran every iteration it was asked to. The lowerings were attempted
// and refused.
//
// What starved them is OCCUPANCY: the allocating side holds a page ACROSS a
// preemption point, descheduled between NewSized and Destroy while owning the
// contended resource, whereas the retuner holds nothing while it waits. So load
// does not slow the two sides equally — it inflates occupancy on one side only,
// pins usage at the ceiling, and makes every lowering legitimately refusable.
// The storm's design rests on usage sitting at the raised ceiling "a minority of
// the time", and that minority is a function of load.
//
// The arrangement below answers that specifically rather than incidentally, by
// making occupancy an INPUT instead of an outcome. Each admitting actor takes
// exactly one page and holds it to the end of the round, so the pages held are
// the shape's own numbers rather than whatever the scheduler left in flight; and
// supply() subtracts the pre-held pages while deliberately NOT counting the ones
// the draining actors give back, so every round is sized for its own worst-case
// occupancy. A round cannot be starved by a page being held, because the page
// being held is what it was arranged around.
//
// So this version arranges the contest instead of hoping for it. A round
// releases a fixed cast from one line: actors that each attempt EXACTLY ONE
// page-sized admission, actors that each destroy exactly one pre-held enclave,
// and one retuner that raises the budget by a page and immediately withdraws
// one. Every claim in the round is one page, the cast is fixed, and nothing
// loops — so supply and demand are known before the round opens, and
// min(supply, demand) of the claims must be granted whatever order they land
// in. The shrinking half of the retune path is exercised BY CONSTRUCTION in the
// shapes where supply covers demand, which is what makes the controls stop
// being load-sensitive: they now fail when the code is broken and at no other
// time.
//
// Three shapes, each proving something the others cannot:
//
//   - slack: supply exactly covers demand, so all eight admissions and the
//     lowering succeed on every host. This is the shape that guarantees the
//     shrinking path runs — a lowering landing while eight admissions are live
//     — and it holds under GOMAXPROCS=1 as firmly as on eight cores.
//   - contested: two pages short, so exactly two claims are refused and the
//     rest are granted. This is the linearization test: if a lowering and an
//     admission share a page, one more claim is granted than the budget can pay
//     for and the count says so. That detection still needs the two to actually
//     overlap, which needs more than one core — see the mutation note below.
//   - draining: destroys land inside the window, so a lowering decides while
//     reservations are being returned to it, and the accounting has to come out
//     exact anyway.
//
// # What each round asserts
//
//   - The free counter is never negative. That is over-commit in its most
//     direct form, sampled by every goroutine at every point where a racing
//     pair could have double-spent, and checked again after the join.
//   - Exactly granted() claims succeeded — not fewer (a starved round would say
//     so instead of quietly proving less) and not more (the over-commit).
//   - Every admitting actor recorded an outcome, so a goroutine that returned
//     early cannot be mistaken for a refusal.
//   - InUse is exactly the pages the admitted enclaves hold, and Limit is the
//     lowered budget or the raised one according to whether the withdrawal won.
//   - After the round's enclaves are destroyed the allocator is whole again:
//     nothing leaked a reservation, and Available is back at Limit.
//
// # Mutation notes
//
// Replacing the compare-and-swap in withdrawLocked with a check followed by an
// unconditional add is caught by the contested rounds, which report one more
// granted claim than the budget could pay for, and by the free-counter witness.
// It is caught on multi-core runs; on a single core the window between the
// check and the add is almost never preempted, so a GOMAXPROCS=1 run of this
// test proves the arrangement holds, not that the race is detectable there.
// Breaking the lowering path — a withdrawLocked that refuses, a SetLimit that
// forgets to store the lowered shadow — fails the slack and draining rounds
// directly and by name, before the vacuity control at the bottom is reached.
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
	// Controls. Without these the rounds above could have admitted nothing, or
	// never contended, and still reported green. They are now backed by the
	// shapes rather than by the scheduler: the slack and draining rounds cannot
	// finish without a successful lowering, and the contested rounds cannot
	// finish without a refused admission.
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

// runRetuneShape runs one shape's rounds against a fixed cast of goroutines,
// checking each round as it completes and adding what it did to the run-wide
// tally.
//
// The cast is created once and reused for every round, released round by round
// from a channel closed by the coordinator. Long-lived participants are not an
// optimization: goroutines that are already running and already hot are the
// ones most likely to reach the line together, and a cast recreated per round
// spends the window being scheduled for the first time.
func runRetuneShape(t *testing.T, sh retuneShape, tally *retuneTally) {
	// Harness self-checks. Both of these are properties of the SHAPE, so a
	// future edit that breaks the arithmetic fails here with the reason rather
	// than in a round assertion that looks like a product defect.
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
	witness := func(a *Allocator) {
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
					// The raise puts the contested page into circulation, and it
					// happens BEFORE the line on purpose. A raise only adds
					// headroom, so it has nothing to race and nothing to
					// double-spend. Leaving it inside the window spends the
					// opening of the contest taking a mutex and writing two
					// words while the admitting actors are already past their
					// compare-and-swap — a head start for one side, measured as
					// refusedLower=0 across 200 contested rounds, meaning the
					// withdrawal never once had to fight for the page the round
					// was arranged to make it fight for. Out here the retuner
					// waits at the line with everyone else, and the withdrawal
					// reaches the counter with the admissions.
					if err := rd.a.SetLimit((rd.shape.limit + 1) * pageSize); err != nil {
						t.Errorf("%s round %d: SetLimit(raise): %v", rd.shape.name, r, err)
						// Arrive at the line anyway. The rest of the cast is
						// waiting for a full house, and a retuner that walked
						// off would trade this named error for two hundred
						// thirty-second stalls and a suite timeout.
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
					e, err := rd.a.NewSized(32)
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
		a, err := NewAllocator(sh.limit * pageSize)
		if err != nil {
			t.Errorf("%s round %d: NewAllocator: %v", sh.name, r, err)
			closeFrom = r
			break
		}
		rd := &retuneRound{
			shape: sh,
			a:     a,
			held:  make([]*MemoryEnclave, sh.drain),
			got:   make([]*MemoryEnclave, sh.admit),
		}
		bad := false
		for i := range rd.held {
			e, err := a.NewSized(32)
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
			// One diagnosed round is the diagnosis; two hundred copies of it
			// are noise on top of it.
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

// checkRetuneRound asserts everything one completed round has to be true of.
// The claims are stated as arithmetic on the shape, so they hold on every host
// and under every interleaving; a round that does not satisfy them is a defect
// in the allocator or in the harness, never a slow machine.
func checkRetuneRound(t *testing.T, r int, rd *retuneRound) {
	sh := rd.shape
	admitted := rd.admitted.Load()
	refused := rd.refused.Load()
	lowered := rd.lowered.Load()

	if free := rd.a.free.Load(); free < 0 {
		t.Errorf("%s round %d: free = %d after the round: a lowering and an admission both took the same page",
			sh.name, r, free)
	}
	// Every actor accounted for. Without this an actor that returned early
	// would look exactly like one whose admission was refused, and the count
	// below would balance for the wrong reason.
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

// TestAllocator_Retune_LoweringLosesTheContestedPage is the deterministic half
// of the retune/admission race: it parks a budget lowering at the hazard point
// and lands the conflicting admission by hand, so the interleaving the
// compare-and-swap exists for happens on every run rather than when the
// scheduler obliges.
//
// [TestAllocator_Retune_RacesAdmission] arranges the same contest at scale and
// proves it comes out right under real concurrency, but WHICH interleaving it
// gets is still the scheduler's to give. Measured against a withdrawLocked
// regressed from compare-and-swap to read-then-subtract, on an ordinarily
// loaded 8-core host: the storm form of that test went red 3 times in 10, the
// arranged form 0 times in 10, and this test 25 times in 25 — multi-core,
// GOMAXPROCS=1 and `taskset -c 0` alike. A race test that catches the
// regression it was written for on a third of its runs is a coin flip wearing a
// concurrency hat, and the fix is to stop hoping for the window and enter it.
//
// The arrangement: an allocator with exactly ONE page of headroom, so the
// lowering and the admission want the same page and only one of them can have
// it.
//
//  1. A goroutine calls SetLimit(0). Inside withdrawLocked it reads free = one
//     page, decides the page is there, and parks on the seam BEFORE the swap.
//  2. This goroutine then admits that page. It must succeed: the withdrawal has
//     not committed anything yet, and an admission refused here would mean the
//     budget had been spent by a decision that had not been made.
//  3. The withdrawal is released. Its compare-and-swap now fails — the counter
//     is not what it read — so it loops, sees no headroom, and refuses.
//
// What must be true afterwards is the whole contract of the free counter: the
// admission holds the page, the budget is untouched because a refused lowering
// changes nothing, and the counter is zero rather than negative. Read
// differently, the run is the over-commit as it would actually happen: a
// withdrawal that acted on a stale read would report success, leave a zero
// budget with a page reserved against it, and drive free to -1.
//
// The reverse window — an admission parked while a lowering lands — is not
// tested this way on purpose. It would need the same seam inside reserve, which
// is the lock-free path every allocation in the process goes through and the
// one place this package will not accept an instrumentation branch; the
// contested rounds of [TestAllocator_Retune_RacesAdmission] cover that
// direction at scale instead.
func TestAllocator_Retune_LoweringLosesTheContestedPage(t *testing.T) {
	a, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	parked := make(chan struct{})
	resume := make(chan struct{})
	var (
		park    sync.Once
		release sync.Once
	)
	// releaseParked lets the withdrawal out of the seam, and it is idempotent
	// because two paths call it: the ordinary one below, and the cleanup that
	// covers the failure paths. A t.Fatalf between the park and the release
	// would otherwise leave that goroutine blocked forever — and blocked
	// HOLDING a.mu, since SetLimit's deferred Unlock has not run. Nothing joins
	// it, so it would not hang the suite; it would sit there for the life of
	// the process holding a lock, which is the kind of leak that turns one
	// clean failure into two confusing ones the day this package grows a
	// goroutine-leak check.
	releaseParked := func() { release.Do(func() { close(resume) }) }
	t.Cleanup(releaseParked)
	// Set before the withdrawing goroutine is started and never touched again,
	// so the seam needs no synchronization of its own.
	//
	// One-shot, and the reason is the close rather than the park: the
	// withdrawal's compare-and-swap loop reaches the seam again after its swap
	// fails, and a second close(parked) panics. The second park would be
	// harmless on its own, since resume is already closed by then.
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
		// The seam is the entire mechanism. If the withdrawal never reaches it
		// the run proves nothing, and saying so is the difference between a
		// harness that broke and a test that passed.
		t.Fatalf("the withdrawal never reached the seam in withdrawLocked; the contest was never staged and this test proves nothing")
	}

	// The conflicting admission, made while the withdrawal is parked between
	// its read of the counter and the swap that acts on it.
	e, err := a.NewSized(32)
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
		t.Errorf("SetLimit(0) = %v, want a LimitError matching ErrBudgetInUse", lowerErr)
	}

	// And the reservation still returns, so the refusal left nothing behind.
	e.Destroy()
	if got, want := a.Available(), pageSize; got != want {
		t.Errorf("Available = %d after Destroy, want %d", got, want)
	}
}

// TestAllocator_TransferTo_ConcurrentOppositeDirections is the deadlock test. Two
// goroutines transferring A→B and B→A at once is the wait-for cycle the id
// ordering exists to make unconstructible; a regression to "lock the receiver
// first" hangs here rather than failing an assertion, which is why the wait is
// bounded.
//
// It runs allocation traffic against both allocators at the same time, so the
// budgets are moving while they are being drawn against — and asserts the two
// properties that must survive that: neither allocator ever over-commits, and
// the total budget across the pair is conserved to the byte.
func TestAllocator_TransferTo_ConcurrentOppositeDirections(t *testing.T) {
	a, err := NewAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	b, err := NewAllocator(8 * pageSize)
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

	// The ALLOCATIONS bound the run and the transfers run for exactly as long as
	// they last. Which side drives termination is the whole reliability story
	// here, and both of the other arrangements were measured failing:
	//
	//   - Fixed iteration counts on both sides, no coordination. Codex measured
	//     `moved=86 refused=2914 admitted=0 finalLimits=0/65536`: the transfers
	//     had migrated the entire budget into one allocator and the allocation
	//     loops ran out their iterations against the drained one. Green, having
	//     asserted nothing about a transfer racing an admission.
	//   - Transfers bounded, allocations looping until the transfers stop. This
	//     passed 60/60 on this host and failed 11/40 under GOMAXPROCS=1: on one
	//     core the transfer goroutines ran to completion before the allocation
	//     goroutines were ever scheduled, so the stop signal was already closed
	//     when they first looked at it and they did zero iterations.
	//
	// With the allocations bounded instead, they cannot be skipped by any
	// scheduling order — nothing else can close their loop — and the transfers
	// cannot finish first, because they only stop when the allocations do.
	const allocIterations = 400
	var wg sync.WaitGroup

	start := make(chan struct{})
	allocDone := make(chan struct{})
	var allocsLeft atomic.Int64
	allocsLeft.Store(2)

	transfer := func(from, to *Allocator) {
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

	// alloc falls back to the other allocator on a refusal, because the
	// transfers can drain either side to a zero budget and a goroutine tied to
	// one allocator can legitimately be refused for the whole run.
	//
	// The fallback makes an admission very likely, NOT certain, and the
	// difference is worth stating because the first version of this comment got
	// it wrong. The reasoning that looks airtight is: the two budgets always sum
	// to sixteen pages however they are distributed, at most two of which these
	// goroutines can have reserved, so at any INSTANT at least one of the pair
	// has headroom and an iteration trying both cannot be refused by both. The
	// flaw is "instant": the two attempts are made at different times, and a
	// great many transfers can run between them. A goroutine can be refused by
	// an empty b, be descheduled while the whole budget migrates from a into b,
	// and then be refused by a now-empty a. Both refusals are individually
	// correct. Measured: one such iteration in a 60-run sweep, which is why
	// refusedBoth is logged rather than asserted to be zero — it was, until the
	// sweep found the counterexample.
	alloc := func(primary, fallback *Allocator) {
		defer wg.Done()
		// Closed on every exit path, the error returns included, so a failing
		// allocation goroutine releases the transfer goroutines rather than
		// leaving them spinning until the bounded wait fires.
		defer func() {
			if allocsLeft.Add(-1) == 0 {
				close(allocDone)
			}
		}()
		<-start
		for i := 0; i < allocIterations; i++ {
			e, err := primary.NewSized(32)
			witness()
			if err != nil {
				if !errors.Is(err, ErrBudgetExhausted) {
					t.Errorf("unexpected NewSized err: %v", err)
					return
				}
				if e, err = fallback.NewSized(32); err != nil {
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

// TestInUseFrom covers the arithmetic that turns a (budget, headroom) pair into
// a reserved-byte count, at the boundaries where it stops being obvious.
//
// The interesting rows are the ones with a NEGATIVE free — an over-subscribed
// allocator — beside a large budget, because that is the only combination whose
// difference can exceed int64, and the ones with free ABOVE limit — headroom
// read before a lowering — which go negative without wrapping (#83). Deleting
// the guard makes both kinds report a negative byte count; narrowing it to the
// wrap alone (free < 0) lets the stale rows through, which was the defect; and
// widening it to refuse any pair a consistent allocator can hold breaks the
// ordinary rows.
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
		// The other skew, and the one the free < 0 guard missed (#83): a
		// headroom reading from BEFORE a lowering, beside the lowered limit.
		// Nothing wraps here -- limit-free is an ordinary subtraction -- and
		// the result is negative because the pair is stale, not because it
		// is wide. A consistent pair never has free above limit, so this is
		// unrepresentable for the same reason a wrap is.
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

// TestAllocator_budgetSnapshot_FallsBackWhenSkewed drives the fallback branch
// deterministically, by handing budgetSnapshot the one thing a lock-free reader
// can legitimately be holding and the allocator cannot be in: a stale, negative
// headroom reading from before a raise, beside a limit that has already been
// raised.
//
// The allocator itself is left in a CONSISTENT state, which is what the fallback
// relies on — it takes the read lock precisely to read that state instead of the
// skewed pair — so the exact answer is available and the test can assert it
// rather than merely assert non-negativity.
func TestAllocator_budgetSnapshot_FallsBackWhenSkewed(t *testing.T) {
	a, err := NewAllocator(pageSize)
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

// TestAllocator_budgetSnapshot_FallsBackWhenLoweredUnderAStaleRead is the
// regression for the second window into a negative InUse (#83), which needs no
// over-subscription and no extreme budget at all.
//
// An empty allocator with two pages free. One goroutine asks for three pages
// and is refused, having loaded free = 2 pages; before it loads the limit to
// describe the refusal, another goroutine quiesces the allocator with
// SetLimit(0). The refusal then pairs a limit of 0 with a headroom of two
// pages and reports InUse = -2 pages -- not a wrap, so the wrap-only guard let
// it through, and BudgetError documents InUse as never negative.
//
// That window is as narrow as the other one, so the test hands budgetSnapshot
// the stale reading directly, exactly as
// TestAllocator_budgetSnapshot_FallsBackWhenSkewed does. The allocator itself is
// settled at (0, 0), so the exact answer is known.
func TestAllocator_budgetSnapshot_FallsBackWhenLoweredUnderAStaleRead(t *testing.T) {
	a, err := NewAllocator(2 * pageSize)
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

// TestAllocator_Refusal_NeverReportsNegativeInUse drives the real window rather
// than a hand-made pair: an over-subscribed allocator is raised to the largest
// expressible budget and dropped back, over and over, while other goroutines
// collect refusals. Every BudgetError one of them sees must carry a byte count
// that could have happened.
//
// The over-subscription is what makes the window reachable at all — it is the
// only way free goes negative — so the live enclave below is load-bearing and
// not scaffolding.
//
// It does reach the window, and that is measured rather than assumed: removing
// the guard in inUseFrom fails this test on 19/20 runs at -cpu=8 and 10/10 at
// -cpu=2, at 37 to 3037 wrapped readings each. Those figures were re-measured
// for #75, which changed what ends the run, and they replace the 5/5 at 18 to
// 37 readings the first version was measured at. Like the other race tests
// here it needs parallelism — the same broken build is caught on 1/10
// single-core runs — which is why
// TestAllocator_budgetSnapshot_FallsBackWhenSkewed exists alongside it and
// drives the same window deterministically.
//
// Note what this test can and cannot see. It asserts only that the reported
// count is POSSIBLE, so it dies on a raw subtraction that wraps but not on an
// implementation that detects the skew and gives up, reporting zero. The exact
// figure is the deterministic test's job.
func TestAllocator_Refusal_NeverReportsNegativeInUse(t *testing.T) {
	a, err := NewAllocator(2 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	// One page reserved, then a budget of zero: free is now -pageSize and the
	// allocator refuses everything.
	hold, err := a.New(material())
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

	// Each side has a floor of its own and stops only once the other side has
	// reached its floor, for the reason spelled out in
	// TestAllocator_TransferTo_ConcurrentOppositeDirections: whichever side can
	// be cut short by a scheduling order is the side that reports green having
	// done nothing.
	//
	// So the RETUNERS carry both floors — their own iteration count and the
	// shared refusal target — and the refusers sample for as long as there is
	// a retuner running. That is the correction #75 is about: the retuners
	// used to stop at retuneIterations alone, which decided the length of the
	// run by a counter the assertion below does not read. A refuser iteration
	// is not a refusal — a raise to MaxInt64 admits, and an admitted iteration
	// counts for nothing — so on a host where the refusers were mostly
	// admitted the window closed on however few refusals had been seen in it.
	// Measured on a factory runner at load average ~26: 231 of them, and the
	// vacuity guard fired on a test that had never stopped working.
	//
	// It matters WHICH side carries the refusal target, and the first version
	// of this fix put it on the wrong one. Letting a refuser return as soon as
	// the shared count was met looks equivalent and is not: this allocator
	// refuses from a standing start, with a zero budget and a negative free,
	// so two refusers scheduled before the retuners can collect the whole
	// target off that static pair and be gone before a single retune lands.
	// The retuners then run their 4000 iterations with nobody watching, and
	// both assertions pass against a build with the wrap guard REMOVED —
	// measured 18/18 green at -cpu=1,2,8 with a 2ms delay forcing that order,
	// every reading the unskewed 0-(-pageSize). Caught by codex on review of
	// PR #79. A refuser that stops early is a refuser that stopped sampling,
	// which is the same vacuity the guard exists for, one level down. With the
	// target moved onto the retuners that same forced order kills the same
	// broken build on 10/10 runs at -cpu=8 and 9/10 at -cpu=2.
	//
	// The regime the issue reports reproduces on demand, which is how the
	// bound was checked rather than argued: a 50µs sleep inserted between the
	// raise and the drop — a retuner preempted mid-cycle, which is what a
	// loaded host does to it — holds the budget open so the refusers are
	// ADMITTED rather than refused. Against that simulation the old bound
	// failed 2 of 4 runs, at 143 and 199 refusals, which is the shape reported
	// in #75; this one collected its 500 on 6 of 6.
	retune := func() {
		defer wg.Done()
		defer func() {
			if retunersLeft.Add(-1) == 0 {
				close(retunersDone)
			}
		}()
		<-start
		// retuneIterations is a floor here, not a ceiling: past it the
		// retuners keep widening the window until the refusers have their
		// count, so a starved refuser is given MORE window rather than less.
		// Both floors, because either alone is a run that can assert nothing —
		// the iteration count without the refusal target is the #75 failure,
		// and the refusal target without the iteration count would let a
		// single lucky retune satisfy the whole run.
		for i := 0; ; i++ {
			if i >= retuneIterations && refusals.Load() >= minRefusals {
				return
			}
			// refusersDone is closed on every refuser exit path, the error
			// returns included, so a failing refuser releases the retuners
			// rather than leaving them spinning until the bounded wait fires.
			// Nothing else closes it: a healthy refuser stops only when the
			// retuners do, so this is not a second way to end a healthy run.
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
		// The refusers have no floor of their own and no count to reach: they
		// sample until the last retuner has stopped, which is the only state
		// in which another sample could tell us anything. Bounded, because a
		// retuner stops on its own two floors.
		for {
			select {
			case <-retunersDone:
				return
			default:
			}
			e, err := a.NewSized(32)
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

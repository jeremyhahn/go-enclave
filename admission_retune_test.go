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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

// TestAllocator_Retune_RacesAdmission is the test this change exists to pass. A
// two-page budget with eight goroutines each taking a page, against eight
// goroutines withdrawing a page and giving it back, keeps the free counter
// hovering around zero: every admission and every lowering competes for the same
// last page, so the two decisions cannot both be right unless they are
// linearized against each other.
//
// The shape of the contest was chosen against two measurements, both of which
// left it asserting far less than it appears to.
//
// A ONE-page budget starves the allocators: a run measured twelve admissions
// against twenty-four hundred refusals, and a race test where one side almost
// never commits cannot catch the interleaving it exists for. Retuners that
// withdraw a page from a two-page budget starve in the other direction on a
// single core — measured under GOMAXPROCS=1, every one of 2400 lowerings was
// refused, because two of the eight allocator goroutines were always mid-borrow
// when a retuner ran, and the run reported green on a retune path it never once
// executed.
//
// So the retuners RAISE by a page and lower back. The raise always succeeds; the
// lowering back is refused only when usage is at the raised ceiling exactly,
// which is a minority of the time on any core count. Usage still cannot exceed
// three pages against eight allocator goroutines, so the free counter still
// hovers at zero and the contest is still over the last page.
//
// The invariant asserted is that the free counter never goes negative. That is
// the over-commit in its most direct form — free < 0 means the allocator handed
// out locked bytes the budget does not cover, and it is exactly equivalent to
// InUse() exceeding Limit(), but it is a single atomic word so a concurrent
// observer can read it without the two-word skew that InUse and Limit would
// have. Nothing in this test calls ForceLimit, which is the only legitimate way
// to drive it negative.
//
// Meaningful only with more than one core, and that is measured rather than
// assumed: replacing the compare-and-swap in withdrawLocked with a check
// followed by an unconditional add fails this test on every multi-core run and
// passes it on every GOMAXPROCS=1 run, because the window between the check and
// the add is almost never preempted on a single core. The counters at the end
// are what prove the run actually contended rather than executing each goroutine
// to completion in turn.
func TestAllocator_Retune_RacesAdmission(t *testing.T) {
	base := 2 * pageSize
	a, err := NewAllocator(base)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var (
		admitted     atomic.Int64
		refusedAdmit atomic.Int64
		raised       atomic.Int64
		lowered      atomic.Int64
		refusedLower atomic.Int64
		overCommit   atomic.Int64
	)
	// witness samples the admission counter. Called from every goroutine at
	// every point where a racing pair could have double-spent the page.
	witness := func() {
		if a.free.Load() < 0 {
			overCommit.Add(1)
		}
	}

	const goroutines, iterations = 8, 300
	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				e, err := a.NewSized(32)
				witness()
				if err != nil {
					if !errors.Is(err, ErrBudgetExhausted) {
						t.Errorf("unexpected NewSized err: %v", err)
						return
					}
					refusedAdmit.Add(1)
					continue
				}
				admitted.Add(1)
				witness()
				e.Destroy()
				witness()
			}
		}()
	}

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Put a page into circulation, then take it back out. A
				// lowering that races an admission must lose or win outright,
				// never share.
				if err := a.SetLimit(base + pageSize); err != nil {
					t.Errorf("SetLimit(raise): %v", err)
					return
				}
				raised.Add(1)
				witness()
				switch err := a.SetLimit(base); {
				case err == nil:
					lowered.Add(1)
				case errors.Is(err, ErrBudgetInUse):
					refusedLower.Add(1)
				default:
					t.Errorf("unexpected SetLimit(lower) err: %v", err)
					return
				}
				witness()
			}
		}()
	}

	waitBounded(t, &wg, 60*time.Second, "the retune/admission race")

	if n := overCommit.Load(); n != 0 {
		t.Errorf("the allocator over-committed %d times: a lowering and an admission both took the same page", n)
	}
	// Controls. Without these the run above could have admitted nothing, or
	// never contended, and still reported green.
	if admitted.Load() == 0 {
		t.Error("no allocation was ever admitted; this test asserted nothing")
	}
	if lowered.Load() == 0 {
		t.Error("no lowering ever succeeded; the shrinking half of the retune path was never exercised")
	}
	if raised.Load() == 0 {
		t.Error("no raise ever ran; the retuners did nothing")
	}
	if refusedAdmit.Load() == 0 {
		t.Error("nothing was ever refused admission; the goroutines never contended and the race was not exercised")
	}
	t.Logf("admitted=%d refusedAdmit=%d raised=%d lowered=%d refusedLower=%d",
		admitted.Load(), refusedAdmit.Load(), raised.Load(), lowered.Load(), refusedLower.Load())

	// Every enclave was destroyed, so every reservation must have come back: the
	// whole budget is available again, whichever of the two ceilings the last
	// retune happened to leave in force.
	if a.InUse() != 0 {
		t.Errorf("final InUse = %d, want 0 (a reservation or a withdrawal leaked)", a.InUse())
	}
	if a.Available() != a.Limit() {
		t.Errorf("final Available = %d against Limit %d, want them equal", a.Available(), a.Limit())
	}
	if l := a.Limit(); l != base && l != base+pageSize {
		t.Errorf("final Limit = %d, want %d or %d", l, base, base+pageSize)
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
// difference can exceed int64. Deleting the guard makes the MaxInt64 rows report
// a negative byte count; widening it to catch a non-negative free breaks the
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
// the guard in inUseFrom fails this test on 5/5 multi-core runs, at 18 to 37
// wrapped readings each. Like the other race tests here it needs parallelism —
// 3/3 GOMAXPROCS=1 runs pass against the same broken build — which is why
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
	var retunersLeft atomic.Int64
	retunersLeft.Store(2)

	// The refusers have a floor of their own and the retuners run until they
	// are finished, for the reason spelled out in
	// TestAllocator_TransferTo_ConcurrentOppositeDirections: whichever side can
	// be cut short by a scheduling order is the side that reports green having
	// done nothing.
	retune := func() {
		defer wg.Done()
		defer func() {
			if retunersLeft.Add(-1) == 0 {
				close(retunersDone)
			}
		}()
		<-start
		for i := 0; i < retuneIterations; i++ {
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
		<-start
		for i := 0; ; i++ {
			if i >= minRefusals {
				select {
				case <-retunersDone:
					return
				default:
				}
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

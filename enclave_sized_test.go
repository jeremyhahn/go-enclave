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
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"testing"
)

// TestNewMemoryEnclaveSized_ZeroedAndSized covers the two properties the
// constructor's name promises: the enclave is exactly n bytes and every one of
// them is zero. A caller that generates only part of the region — a short read,
// a derivation that fills a prefix — must not find another allocation's remnant
// in the tail.
func TestNewMemoryEnclaveSized_ZeroedAndSized(t *testing.T) {
	for _, n := range []int{1, 32, 4096, 8192} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			e, err := NewMemoryEnclaveSized(n)
			if err != nil {
				t.Fatalf("NewMemoryEnclaveSized(%d): %v", n, err)
			}
			defer e.Destroy()

			if e.Size() != n {
				t.Errorf("Size = %d, want %d", e.Size(), n)
			}
			if !e.IsAlive() {
				t.Error("IsAlive = false on a fresh enclave")
			}
			if err := e.WithBytes(func(b []byte) error {
				if len(b) != n {
					return fmt.Errorf("borrow length = %d, want %d", len(b), n)
				}
				for i, c := range b {
					if c != 0 {
						return fmt.Errorf("byte %d = %#x, want the region zeroed", i, c)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestNewMemoryEnclaveSized_FillsInPlace is the generate-in-place property, and
// the reason this constructor exists.
//
// It is asserted as ALIASING, not as a happy return: material written through
// one borrow must be visible through the next. A borrow that handed out a copy
// — or a buffer memguard had frozen read-only, as it freezes every enclave
// built from existing material — would leave the second borrow reading zeroes,
// so both mutations turn this red. Together with the mlock proof in
// TestNewMemoryEnclaveSized_MemoryIsLocked (Linux), that establishes the
// property the issue asks for: the bytes the generator produces land in locked
// memory and nowhere else. No third assertion is available for "no heap copy",
// because the API takes no []byte at all — there is no other place for a copy
// to be.
func TestNewMemoryEnclaveSized_FillsInPlace(t *testing.T) {
	const n = 32

	e, err := NewMemoryEnclaveSized(n)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer e.Destroy()

	// The yardstick is derived from the fill itself and kept independent of
	// the enclave: what the generator produced, recorded as it was produced.
	want := make([]byte, n)

	if err := e.WithBytes(func(key []byte) error {
		// Exactly the shape the doc comment prescribes: the CSPRNG writes
		// straight into the locked pages, never into an intermediate slice.
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return err
		}
		copy(want, key)
		return nil
	}); err != nil {
		t.Fatalf("fill: %v", err)
	}

	if bytes.Equal(want, make([]byte, n)) {
		t.Fatal("the generator produced all zeroes; the test would be vacuous")
	}

	// A SEPARATE borrow. If the first one wrote to a copy, this reads zeroes.
	got := make([]byte, n)
	if err := e.WithBytes(func(b []byte) error {
		copy(got, b)
		return nil
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("second borrow saw %x, want the material written by the first (%x)", got, want)
	}

	// EqualTo reads the same storage through the locked accessor.
	if !e.EqualTo(want) {
		t.Error("EqualTo = false for the material generated into the enclave")
	}
}

// TestNewMemoryEnclaveSized_RejectsNonPositive asserts the size guard, and that
// it decides BEFORE memguard is entered.
//
// The error type is what proves the ordering. memguard's own answer to a size
// below one is a dead buffer rather than a panic, so lockedEnclave would report
// it as ErrLockedMemoryUnavailable; getting ErrInvalidSize instead can only mean
// the guard ran first. Delete the guard and this test fails on the sentinel,
// not merely on a message.
func TestNewMemoryEnclaveSized_RejectsNonPositive(t *testing.T) {
	for _, n := range []int{0, -1, -4096} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			e, err := NewMemoryEnclaveSized(n)
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("err = %v, want ErrInvalidSize", err)
			}
			if errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Error("the request reached memguard; the size guard did not run first")
			}
			if e != nil {
				t.Error("a non-nil enclave was returned on error")
			}
		})
	}
}

// TestNewMemoryEnclaveSized_Lifecycle covers the destroyed contract for an
// enclave that was filled rather than moved into: the material is gone, and
// every accessor reports ErrEnclaveDestroyed instead of touching unmapped pages.
func TestNewMemoryEnclaveSized_Lifecycle(t *testing.T) {
	e, err := NewMemoryEnclaveSized(16)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}

	material := bytes.Repeat([]byte{0xA5}, 16)
	if err := e.WithBytes(func(b []byte) error {
		copy(b, material)
		return nil
	}); err != nil {
		t.Fatalf("fill: %v", err)
	}
	if !e.EqualTo(material) {
		t.Fatal("EqualTo = false immediately after the fill")
	}

	e.Destroy()
	e.Destroy() // idempotent

	if e.IsAlive() {
		t.Error("IsAlive = true after Destroy")
	}
	if e.Size() != 0 {
		t.Errorf("Size = %d after Destroy, want 0", e.Size())
	}
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("WithBytes err = %v, want ErrEnclaveDestroyed", err)
	}
	if _, err := e.Open(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open err = %v, want ErrEnclaveDestroyed", err)
	}
	if e.EqualTo(material) {
		t.Error("EqualTo = true on a destroyed enclave")
	}
}

// TestNewMemoryEnclaveSized_ConcurrentBorrowsAndDestroy runs the scoped-borrow
// paths of a filled sized enclave against a concurrent Destroy, matching the
// coverage the move-in constructor already has. Under -race this catches an
// access that escapes the enclave's lock; without it, a read of a destroyed
// buffer. The fill completes before any of it starts, which is the discipline
// the constructor documents.
func TestNewMemoryEnclaveSized_ConcurrentBorrowsAndDestroy(t *testing.T) {
	material := bytes.Repeat([]byte{0x5A}, 24)

	for i := 0; i < 50; i++ {
		e, err := NewMemoryEnclaveSized(len(material))
		if err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
		}
		if err := e.WithBytes(func(b []byte) error {
			copy(b, material)
			return nil
		}); err != nil {
			t.Fatalf("fill: %v", err)
		}

		var wg sync.WaitGroup
		for r := 0; r < 8; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = e.WithBytes(func(b []byte) error {
					// Either the material or a destroyed enclave is correct; a
					// half-visible region is not.
					if len(b) != 0 && !bytes.Equal(b, material) {
						t.Errorf("borrow saw %x, want %x", b, material)
					}
					return nil
				})
				_ = e.EqualTo(material)
				_ = e.Size()
				_ = e.IsAlive()
				_ = e.String()
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Destroy()
		}()

		wg.Wait()

		if e.IsAlive() {
			t.Fatal("enclave alive after Destroy")
		}
	}
}

func TestAllocator_NewSized_Admits(t *testing.T) {
	limit := 4 * pageSize
	a, err := NewAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	const n = 48
	e, err := a.NewSized(n)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}
	defer e.Destroy()

	// Charged the page it actually locks, not the 48 bytes requested.
	if a.InUse() != pageSize {
		t.Errorf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
	if a.Available() != limit-pageSize {
		t.Errorf("Available = %d, want %d", a.Available(), limit-pageSize)
	}
	if e.Size() != n {
		t.Errorf("Size = %d, want %d", e.Size(), n)
	}

	want := make([]byte, n)
	if err := e.WithBytes(func(key []byte) error {
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return err
		}
		copy(want, key)
		return nil
	}); err != nil {
		t.Fatalf("fill: %v", err)
	}
	if !e.EqualTo(want) {
		t.Error("an admitted sized enclave did not hold what was generated into it")
	}
}

// TestAllocator_NewSized_RefusesOverBudget asserts admission gates the sized
// constructor the same way it gates New: over-budget is refused with
// ErrBudgetExhausted, no enclave comes back, and the counter is untouched.
//
// That the refusal happens before memguard is a separate claim, proved under an
// injected lock fault in TestAllocator_NewSized_RefusalNeverEntersMemguard
// (Linux) — a typed error alone cannot show it, since ErrLockedMemoryUnavailable
// is typed too and would mean the purge already ran.
func TestAllocator_NewSized_RefusesOverBudget(t *testing.T) {
	// One page of budget holds exactly one enclave, however small.
	a, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	first, err := a.NewSized(24)
	if err != nil {
		t.Fatalf("first NewSized: %v", err)
	}
	defer first.Destroy()

	before := a.InUse()
	e, err := a.NewSized(16)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("over-budget NewSized err = %v, want ErrBudgetExhausted", err)
	}
	if e != nil {
		t.Error("over-budget NewSized returned a non-nil enclave")
	}
	if a.InUse() != before {
		t.Errorf("InUse = %d after refusal, want unchanged %d", a.InUse(), before)
	}

	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("err is not a *BudgetError: %v", err)
	}
	// Locked bytes throughout: 16 bytes of material costs a page, and the page
	// already taken is what leaves no room.
	if be.Requested != pageSize || be.Limit != pageSize || be.InUse != pageSize {
		t.Errorf("BudgetError = %+v, want Requested=InUse=Limit=%d", be, pageSize)
	}
}

// TestAllocator_NewSized_RejectsNonPositive asserts the size guard runs ahead of
// admission as well as ahead of memguard: an impossible size is neither charged
// to the budget nor reported as a budget refusal.
func TestAllocator_NewSized_RejectsNonPositive(t *testing.T) {
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	for _, n := range []int{0, -1, -4096} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			e, err := a.NewSized(n)
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("err = %v, want ErrInvalidSize", err)
			}
			if errors.Is(err, ErrBudgetExhausted) || errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Errorf("err = %v; the size guard did not run first", err)
			}
			if e != nil {
				t.Error("a non-nil enclave was returned on error")
			}
			if a.InUse() != 0 {
				t.Errorf("InUse = %d after an invalid size, want 0 (no reservation)", a.InUse())
			}
		})
	}
}

// TestAllocator_reserve_RefusesNonPositive asserts the gate's counter invariant
// directly, because the public surface cannot see it.
//
// NewSized's own failure path returns whatever it reserved, so a bad reservation
// of -1 bytes is charged and refunded within the one call and InUse reads 0
// either way — a test that only watched NewSized would pass with the check
// deleted. What a concurrent caller would see is the window in between: a
// counter below zero means a budget larger than the limit, and any allocation
// admitted during that window overshoots. Asserting on reserve is the only place
// that window is observable, so the check lives here and is tested here.
func TestAllocator_reserve_RefusesNonPositive(t *testing.T) {
	limit := 16 * pageSize
	a, err := NewAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	for _, n := range []int64{0, -1, -4096} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			if _, err := a.reserve(n); !errors.Is(err, ErrInvalidSize) {
				t.Errorf("reserve(%d) = %v, want ErrInvalidSize", n, err)
			}
			if got := a.InUse(); got != 0 {
				t.Errorf("InUse = %d after reserve(%d), want 0 (the counter was touched)", got, n)
			}
			if got := a.Available(); got != limit {
				t.Errorf("Available = %d after reserve(%d), want the full %d", got, n, limit)
			}
		})
	}

	// The gate still admits a legitimate reservation afterwards, and charges it
	// the page it will actually cost rather than the 64 bytes asked for.
	charge, err := a.reserve(64)
	if err != nil {
		t.Fatalf("reserve(64) after the refusals: %v", err)
	}
	if charge != pageSize {
		t.Errorf("reserve(64) charged %d, want one page (%d)", charge, pageSize)
	}
	if a.InUse() != pageSize {
		t.Errorf("InUse = %d, want %d", a.InUse(), pageSize)
	}
}

// TestLockedSize pins the accounting unit itself: an enclave costs its size
// rounded UP to a whole page, so everything under a page costs a page.
//
// The exported helper exists because a caller cannot size a budget without it
// — the change this test guards is what makes Limit comparable to
// RLIMIT_MEMLOCK, and a hundred 32-byte credentials need a hundred pages of
// budget, not 3200 bytes.
func TestLockedSize(t *testing.T) {
	p := int(pageSize)
	for _, tc := range []struct {
		in   int
		want int64
	}{
		{1, pageSize},
		{32, pageSize},
		{p - 1, pageSize},
		{p, pageSize},
		{p + 1, 2 * pageSize},
		{2 * p, 2 * pageSize},
		{2*p + 1, 3 * pageSize},
	} {
		if got := LockedSize(tc.in); got != tc.want {
			t.Errorf("LockedSize(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}

	// Not a size any enclave can have: no rounding is defined, so no cost is
	// reported.
	for _, n := range []int{0, -1, -4096} {
		if got := LockedSize(n); got != 0 {
			t.Errorf("LockedSize(%d) = %d, want 0", n, got)
		}
	}

	// The platform maximum is refused on every platform, and after Codex round
	// 2 on PR #8 it is refused for a second reason as well: even where the data
	// region rounds representably, memguard's mapping is that region PLUS two
	// guard pages, laid out in int arithmetic. So the largest constructible
	// enclave stops short of the platform maximum by those guard pages, and
	// anything past it reports 0 — "not a size any enclave can have".
	//
	// Round 1 of that review argued the return type had to be int64 because a
	// 32-bit platform could produce a locked size above MaxInt32. That reason is
	// now GONE: the guard-page ceiling keeps every valid answer inside int on
	// both word sizes. int64 stays because it matches NewAllocator's budget, and
	// this comment records that the original justification did not survive.
	maxIntV := int(^uint(0) >> 1)
	if got := LockedSize(maxIntV); got != 0 {
		t.Errorf("LockedSize(maxInt) = %d, want 0", got)
	}
	if got := LockedSize(maxIntV - int(pageSize)); got != 0 {
		t.Errorf("LockedSize(maxInt-page) = %d, want 0 (the mapping needs two guard pages too)", got)
	}

	// The boundary itself: the largest size whose data region plus two guard
	// pages still fits, and the first one past it.
	largest := int((maxInt - 2*pageSize) / pageSize * pageSize)
	if got := LockedSize(largest); got != int64(largest) {
		t.Errorf("LockedSize(largest constructible) = %d, want %d", got, largest)
	}
	if got := LockedSize(largest + 1); got != 0 {
		t.Errorf("LockedSize(largest+1) = %d, want 0", got)
	}
}

// TestSizedConstructors_RefuseUnmappableSizes is the regression test for the
// fail-open Codex found in round 2 of PR #8, and it covers BOTH construction
// paths because both reach memguard.
//
// memguard maps roundToPageSize(size) + 2*pageSize in int arithmetic. A size
// whose data region rounds representably can still overflow once the guard pages
// are added; mmap then refuses the nonsense length and core.Panic purges every
// live locked buffer in the process. Measured against v0.2.0-alpha with
// n = MaxInt64-pageSize: admission passed, the request reached memguard, and an
// unrelated canary enclave came back DEAD.
//
// The assertion that matters is the sentinel. ErrInvalidSize means the size was
// refused on this side of the line; ErrLockedMemoryUnavailable would mean the
// request reached memguard and the purge already ran — the failure this exists
// to prevent, wearing a typed error.
//
// The budget is deliberately large enough to admit the rounded charge on both
// word sizes and nothing is pre-reserved, so a refusal here cannot be the budget
// doing the work by accident.
func TestSizedConstructors_RefuseUnmappableSizes(t *testing.T) {
	maxIntV := int(^uint(0) >> 1)

	// A canary that must survive: if the request reaches memguard, the purge
	// destroys it. That is the observable, not just the error value.
	canary, err := NewMemoryEnclave([]byte("canary-key-material"))
	if err != nil {
		t.Skipf("could not allocate the canary enclave: %v", err)
	}
	defer canary.Destroy()

	for _, tc := range []struct {
		name string
		n    int
	}{
		{"platform maximum", maxIntV},
		{"data region rounds, mapping does not", maxIntV - int(pageSize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Unadmitted path first: no Allocator stands in front of it at all,
			// so its own size check is the only thing between the caller and a
			// process-wide purge.
			e, err := NewMemoryEnclaveSized(tc.n)
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("NewMemoryEnclaveSized(%d) = %v, want ErrInvalidSize", tc.n, err)
			}
			if errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Error("the request reached memguard; the size check did not run first")
			}
			if e != nil {
				t.Error("a non-nil enclave was returned")
				e.Destroy()
			}

			// Admitted path, with a budget big enough that admission cannot be
			// what refuses it.
			a, err := NewAllocator(maxInt)
			if err != nil {
				t.Fatalf("NewAllocator: %v", err)
			}
			e, err = a.NewSized(tc.n)
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("NewSized(%d) = %v, want ErrInvalidSize", tc.n, err)
			}
			if errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Error("the request reached memguard; admission failed open")
			}
			if e != nil {
				t.Error("a non-nil enclave was returned")
				e.Destroy()
			}
			if got := a.InUse(); got != 0 {
				t.Errorf("InUse = %d after the refusal, want 0", got)
			}

			if !canary.IsAlive() {
				t.Fatal("an unrelated enclave died: memguard was entered and purged the process")
			}
		})
	}

	if !canary.EqualTo([]byte("canary-key-material")) {
		t.Error("the canary's material did not survive")
	}
}

// TestAllocator_reserve_DoesNotOverflow covers the two arithmetic guards on the
// admission path. Each is a fail-open into memguard's process-wide purge if it
// wraps, and they are asserted separately because a single request cannot
// exercise both — one is caught before the other is ever consulted.
//
// The SIZE guard is the page rounding. The obvious form, `n+pageSize-1` masked
// down, wraps for a large enough n; it also has to leave room for the two guard
// pages memguard maps alongside the data region (see lockedSize).
//
// The BUDGET guard is the predicate itself, the fail-open Codex found on PR #3:
// `used+charge > limit` performs signed addition, and for a large enough charge
// that addition wraps NEGATIVE, passes the comparison, and admits an allocation
// the budget cannot cover.
//
// One asymmetry, stated rather than hidden: the budget wrap is reachable only
// where int is 64 bits. On a 32-bit platform the largest constructible charge is
// bounded by int, far below the point where adding it to the counter could
// overflow an int64. The assertions below hold on both — as a wrap on 64-bit and
// as an ordinary over-budget refusal on 32-bit — but the mutant that restores
// `used+charge > limit` is only caught on 64-bit, and claiming otherwise would
// be false.
func TestAllocator_reserve_DoesNotOverflow(t *testing.T) {
	// Guard 1 — the size. MaxInt64 has no representable page-rounded cost and
	// no mapping that fits, so it is refused as an impossible SIZE before any
	// budget comparison happens. A larger limit would not help, which is why
	// this is ErrInvalidSize and not ErrBudgetExhausted.
	a, err := NewAllocator(math.MaxInt64)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if _, err := a.reserve(1); err != nil {
		t.Fatalf("reserve(1): %v", err)
	}
	if a.InUse() != pageSize {
		t.Fatalf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
	if _, err := a.reserve(math.MaxInt64); !errors.Is(err, ErrInvalidSize) {
		t.Errorf("reserve(MaxInt64) = %v, want ErrInvalidSize", err)
	}
	if got := a.InUse(); got != pageSize {
		t.Errorf("InUse = %d after the refusal, want the unchanged %d", got, pageSize)
	}

	// Guard 2 — the budget predicate. widest is the largest size that clears
	// every size guard, so it reaches the comparison. The budget is exactly its
	// charge and several pages are already spoken for, which makes it over
	// budget on any platform; on 64-bit it is also past the point where
	// used+charge overflows, which is what the restored-predicate mutant needs.
	widest := (maxInt - 2*pageSize) / pageSize * pageSize
	if _, ok := lockedSize(widest); !ok {
		t.Fatalf("lockedSize(%d) refused; the test would never reach the budget predicate", widest)
	}

	w, err := NewAllocator(widest)
	if err != nil {
		t.Fatalf("NewAllocator(widest): %v", err)
	}
	const spokenFor = 4
	for i := 0; i < spokenFor; i++ {
		if _, err := w.reserve(1); err != nil {
			t.Fatalf("reserve(1) #%d: %v", i, err)
		}
	}
	before := w.InUse()
	if before != spokenFor*pageSize {
		t.Fatalf("InUse = %d, want %d", before, spokenFor*pageSize)
	}
	if _, err := w.reserve(widest); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("reserve(widest) = %v, want ErrBudgetExhausted", err)
	}
	if got := w.InUse(); got != before {
		t.Errorf("InUse = %d after the refusal, want the unchanged %d (the counter wrapped)", got, before)
	}

	// The public half, through NewSized. Its job is the memguard arm check:
	// with admission intact the request never enters memguard, and with either
	// guard removed it does and comes back with ErrLockedMemoryUnavailable — a
	// different sentinel, from the far side of the purge.
	small, err := NewAllocator(2 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := small.NewSized(int(widest))
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("NewSized(widest) against a two-page budget = %v, want ErrBudgetExhausted", err)
	}
	if errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Error("the request reached memguard; admission failed open")
	}
	if e != nil {
		t.Error("NewSized(widest) returned a non-nil enclave")
		e.Destroy()
	}
	if got := small.InUse(); got != 0 {
		t.Errorf("InUse = %d after the refusal, want 0", got)
	}
}

// TestAllocator_NewSized_DestroyReleasesReservation is the release-path mutation
// killer for NewSized, asserted on the ALLOCATOR because the enclave itself
// reads back identically whether or not its reservation was returned: fill the
// budget, confirm the next allocation is refused, destroy the holder, and
// confirm an identical allocation now succeeds. Dropping `e.release = …` from
// NewSized leaves the budget consumed forever and fails the final call.
func TestAllocator_NewSized_DestroyReleasesReservation(t *testing.T) {
	a, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := a.NewSized(16)
	if err != nil {
		t.Fatalf("NewSized (full): %v", err)
	}
	if a.InUse() != pageSize {
		t.Fatalf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
	if _, err := a.NewSized(1); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("NewSized while full err = %v, want ErrBudgetExhausted", err)
	}

	e.Destroy()
	if a.InUse() != 0 {
		t.Fatalf("InUse = %d after Destroy, want 0 (reservation not released)", a.InUse())
	}
	e.Destroy() // idempotent; must not release twice and underflow
	if a.InUse() != 0 || a.Available() != pageSize {
		t.Fatalf("InUse = %d Available = %d after a double Destroy, want 0 and %d", a.InUse(), a.Available(), pageSize)
	}

	e2, err := a.NewSized(16)
	if err != nil {
		t.Fatalf("NewSized after release: %v (budget was not returned)", err)
	}
	e2.Destroy()
}

// TestAllocator_NewSized_Concurrent runs many concurrent generate-fill-verify-
// destroy cycles against a tight budget. The invariants under -race: InUse never
// exceeds the limit at any observed point, each enclave holds exactly what its
// own goroutine generated into it (so no two fills share storage), and the
// counter returns to exactly zero once everything is destroyed.
func TestAllocator_NewSized_Concurrent(t *testing.T) {
	// Budget in PAGES: each enclave costs one whatever its size, so a budget
	// expressed in the requested bytes would refuse every allocation and leave
	// this test asserting nothing while still reporting green. The admitted
	// counter makes that failure mode loud instead of silent.
	const (
		capacity = 5
		size     = 40
	)
	limit := capacity * pageSize
	a, err := NewAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var admitted atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			want := bytes.Repeat([]byte{byte(g)}, size)
			for i := 0; i < 200; i++ {
				e, err := a.NewSized(size)
				if err != nil {
					if !errors.Is(err, ErrBudgetExhausted) {
						t.Errorf("unexpected NewSized err: %v", err)
					}
					continue
				}
				admitted.Add(1)
				if u := a.InUse(); u > limit {
					t.Errorf("InUse = %d exceeded limit %d", u, limit)
				}
				if err := e.WithBytes(func(b []byte) error {
					copy(b, want)
					return nil
				}); err != nil {
					t.Errorf("fill: %v", err)
				}
				if !e.EqualTo(want) {
					t.Error("an enclave did not hold what this goroutine generated into it")
				}
				e.Destroy()
			}
		}(g)
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

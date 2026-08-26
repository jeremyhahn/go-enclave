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
	a, err := NewAllocator(1024)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	const n = 48
	e, err := a.NewSized(n)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}
	defer e.Destroy()

	if a.InUse() != n {
		t.Errorf("InUse = %d, want %d", a.InUse(), n)
	}
	if a.Available() != 1024-n {
		t.Errorf("Available = %d, want %d", a.Available(), 1024-n)
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
	a, err := NewAllocator(32)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	first, err := a.NewSized(24)
	if err != nil {
		t.Fatalf("first NewSized: %v", err)
	}
	defer first.Destroy()

	before := a.InUse()
	e, err := a.NewSized(16) // 24 + 16 = 40 > 32
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
	if be.Requested != 16 || be.Limit != 32 || be.InUse != 24 {
		t.Errorf("BudgetError = %+v, want Requested=16 InUse=24 Limit=32", be)
	}
}

// TestAllocator_NewSized_RejectsNonPositive asserts the size guard runs ahead of
// admission as well as ahead of memguard: an impossible size is neither charged
// to the budget nor reported as a budget refusal.
func TestAllocator_NewSized_RejectsNonPositive(t *testing.T) {
	a, err := NewAllocator(1024)
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
	a, err := NewAllocator(1024)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	for _, n := range []int64{0, -1, -4096} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			if err := a.reserve(n); !errors.Is(err, ErrInvalidSize) {
				t.Errorf("reserve(%d) = %v, want ErrInvalidSize", n, err)
			}
			if got := a.InUse(); got != 0 {
				t.Errorf("InUse = %d after reserve(%d), want 0 (the counter was touched)", got, n)
			}
			if got := a.Available(); got != 1024 {
				t.Errorf("Available = %d after reserve(%d), want the full 1024", got, n)
			}
		})
	}

	// The gate still admits a legitimate reservation afterwards.
	if err := a.reserve(64); err != nil {
		t.Fatalf("reserve(64) after the refusals: %v", err)
	}
	if a.InUse() != 64 {
		t.Errorf("InUse = %d, want 64", a.InUse())
	}
}

// TestAllocator_reserve_DoesNotOverflow covers the fail-open Codex found on PR
// #3: `used+n > limit` performs signed addition, and for a large enough n that
// addition wraps NEGATIVE, passes the budget test, and admits an allocation the
// budget cannot cover.
//
// It is reachable through the public surface because NewSized takes its size
// from the caller as a plain int, with nothing upstream bounding it — unlike
// New, whose size is the length of a slice that had to be allocated first. And
// the consequence is the exact one admission exists to prevent: the request
// reaches memguard, memguard cannot map it, and core.Panic purges every live
// locked buffer in the process.
//
// The public-surface half of this test is therefore also the arm check. With
// the fix it never enters memguard; with `used+n > a.limit` restored it does,
// and comes back with ErrLockedMemoryUnavailable — a different sentinel, from
// the other side of the line.
func TestAllocator_reserve_DoesNotOverflow(t *testing.T) {
	a, err := NewAllocator(math.MaxInt64)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// One byte in, so limit-used is MaxInt64-1 and the wrap is reachable:
	// used+n = 1 + MaxInt64 overflows to MinInt64, which is <= limit.
	if err := a.reserve(1); err != nil {
		t.Fatalf("reserve(1): %v", err)
	}
	if a.InUse() != 1 {
		t.Fatalf("InUse = %d, want 1", a.InUse())
	}

	if err := a.reserve(math.MaxInt64); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("reserve(MaxInt64) = %v, want ErrBudgetExhausted", err)
	}
	if got := a.InUse(); got != 1 {
		t.Errorf("InUse = %d after the refusal, want the unchanged 1 (the counter wrapped)", got)
	}

	// The public half asks for the largest int the PLATFORM has, computed at
	// runtime. Passing math.MaxInt64 to a parameter of type int is a compile
	// error wherever int is 32 bits, which would cost the package its 32-bit
	// buildability (Codex round 2; reproduced with GOARCH=386, and confirmed
	// absent on dev/main before this branch).
	//
	// The budget is that same maximum, so the request is over budget on every
	// platform: n == limit and one byte is already reserved. On a 64-bit build
	// that is also exactly the wrapping case — used+n is 1+MaxInt64 — so this
	// doubles as the arm check there. On a 32-bit build the wrap is out of
	// reach through this constructor (int caps the request at MaxInt32, and
	// the counter is int64 either way), so what remains here is an ordinary
	// over-budget refusal. The gate-level assertion above is where the wrap is
	// covered on every platform: reserve takes an int64.
	maxInt := int(^uint(0) >> 1)

	wide, err := NewAllocator(int64(maxInt))
	if err != nil {
		t.Fatalf("NewAllocator(maxInt): %v", err)
	}
	if err := wide.reserve(1); err != nil {
		t.Fatalf("reserve(1): %v", err)
	}

	e, err := wide.NewSized(maxInt)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("NewSized(maxInt) = %v, want ErrBudgetExhausted", err)
	}
	if errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Error("the request reached memguard; admission failed open")
	}
	if e != nil {
		t.Error("NewSized(maxInt) returned a non-nil enclave")
		e.Destroy()
	}
	if got := wide.InUse(); got != 1 {
		t.Errorf("InUse = %d after the refusal, want the unchanged 1", got)
	}
}

// TestAllocator_NewSized_DestroyReleasesReservation is the release-path mutation
// killer for NewSized, asserted on the ALLOCATOR because the enclave itself
// reads back identically whether or not its reservation was returned: fill the
// budget, confirm the next allocation is refused, destroy the holder, and
// confirm an identical allocation now succeeds. Dropping `e.release = …` from
// NewSized leaves the budget consumed forever and fails the final call.
func TestAllocator_NewSized_DestroyReleasesReservation(t *testing.T) {
	a, err := NewAllocator(16)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := a.NewSized(16)
	if err != nil {
		t.Fatalf("NewSized (full): %v", err)
	}
	if a.InUse() != 16 {
		t.Fatalf("InUse = %d, want 16", a.InUse())
	}
	if _, err := a.NewSized(1); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("NewSized while full err = %v, want ErrBudgetExhausted", err)
	}

	e.Destroy()
	if a.InUse() != 0 {
		t.Fatalf("InUse = %d after Destroy, want 0 (reservation not released)", a.InUse())
	}
	e.Destroy() // idempotent; must not release twice and underflow
	if a.InUse() != 0 || a.Available() != 16 {
		t.Fatalf("InUse = %d Available = %d after a double Destroy, want 0 and 16", a.InUse(), a.Available())
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
	const (
		limit = 200
		size  = 40
	)
	a, err := NewAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

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

	if a.InUse() != 0 {
		t.Errorf("InUse = %d after all destroys, want 0", a.InUse())
	}
	if a.Available() != limit {
		t.Errorf("Available = %d, want the full %d", a.Available(), limit)
	}
}

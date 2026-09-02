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
	"sync"
	"testing"
)

// openBudget is a budget generous enough for one open of sealedMaterial —
// destination plus the transient key page, with slack — expressed in pages so
// it is correct on any page size.
func openBudget(pages int64) int64 {
	return LockedSize(1) * pages
}

// sealForBudgetTest returns a sealed value under a private ModeRootKey sealer,
// so nothing here depends on (or disturbs) the process sealer.
func sealForBudgetTest(t *testing.T) *SealedEnclave {
	t.Helper()
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	t.Cleanup(v.Destroy)
	return v
}

// TestSealedEnclave_OpenWithAdmitsTheDestination is the whole of #17: the
// enclave OpenWith hands back was reserved from the supplied Allocator, so a
// caller that bounds locked memory bounds what opening a credential costs.
//
// The assertion is on InUse, not on success. An OpenWith that ignored the
// Allocator entirely and called the unadmitted constructor would return a
// perfectly good enclave holding perfectly good material, and every
// correctness assertion in this file would still pass — which is exactly why
// the budget has to be READ rather than merely provided.
func TestSealedEnclave_OpenWithAdmitsTheDestination(t *testing.T) {
	v := sealForBudgetTest(t)

	a, err := NewAllocator(openBudget(8))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if before := a.InUse(); before != 0 {
		t.Fatalf("a fresh Allocator reports %d bytes in use; this test attributes everything below to the open", before)
	}

	e, err := v.OpenWith(a)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	defer e.Destroy()

	// The material is right — an admitted open is still an open.
	if !e.EqualTo(sealedMaterial) {
		t.Error("OpenWith returned the wrong material")
	}

	// EXACTLY the destination, which is two assertions in one number: zero
	// would mean OpenWith ignored the Allocator and used the unadmitted
	// constructor (the defect #17 names), and more than this would mean a
	// transient reservation taken during the open — the DEK's — was never
	// returned.
	want := LockedSize(len(sealedMaterial))
	if got := a.InUse(); got != want {
		t.Errorf("after OpenWith the Allocator reports %d bytes in use, want %d "+
			"(the page-rounded destination, and nothing else still held)", got, want)
	}
}

// TestSealedEnclave_OpenWithReturnsTheReservationOnDestroy pins the other half
// of "admitted against that budget": a reservation that is never returned is
// not a budget, it is a slow leak with a counter on it. Open-per-connection is
// the shape #17 is about, so this is the assertion that matters at scale.
func TestSealedEnclave_OpenWithReturnsTheReservationOnDestroy(t *testing.T) {
	v := sealForBudgetTest(t)

	a, err := NewAllocator(openBudget(8))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// Several sequential opens, each destroyed: a budget that leaked one
	// reservation per open would be exhausted well before the last of these.
	const rounds = 6
	for i := 0; i < rounds; i++ {
		e, err := v.OpenWith(a)
		if err != nil {
			t.Fatalf("OpenWith on round %d of %d: %v (a budget sized for one open cannot "+
				"serve the next unless Destroy returns the reservation)", i+1, rounds, err)
		}
		if !e.EqualTo(sealedMaterial) {
			t.Fatalf("round %d returned the wrong material", i+1)
		}
		e.Destroy()

		if got := a.InUse(); got != 0 {
			t.Fatalf("after Destroy on round %d the Allocator still reports %d bytes in use, want 0", i+1, got)
		}
	}
}

// TestSealedEnclave_OpenWithRefusesANilAllocator pins the documented answer to
// the question the issue insisted not be left to chance.
//
// A nil Allocator REFUSES. The alternative — treat nil as "no budget" and
// allocate anyway — would hand the caller precisely the unbudgeted allocation
// they called this method to avoid, on a path that keeps working and keeps
// looking bounded, which is the worst available combination.
func TestSealedEnclave_OpenWithRefusesANilAllocator(t *testing.T) {
	v := sealForBudgetTest(t)

	e, err := v.OpenWith(nil)
	if !errors.Is(err, ErrNilAllocator) {
		t.Errorf("OpenWith(nil) = %v, want ErrNilAllocator: a nil Allocator must not silently "+
			"fall back to an unadmitted allocation", err)
	}
	if e != nil {
		t.Error("OpenWith(nil) returned an enclave; it must allocate nothing")
		e.Destroy()
	}

	// The refusal is about the ARGUMENT and does not depend on the value's
	// state, so a destroyed value reports the same thing. Otherwise the error
	// a caller sees for a lost allocator would depend on lifecycle timing.
	d := sealForBudgetTest(t)
	d.Destroy()
	if _, err := d.OpenWith(nil); !errors.Is(err, ErrNilAllocator) {
		t.Errorf("OpenWith(nil) on a destroyed value = %v, want ErrNilAllocator", err)
	}

	// A nil RECEIVER is a different mistake and keeps its own answer.
	var nilValue *SealedEnclave
	if _, err := nilValue.OpenWith(nil); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("(*SealedEnclave)(nil).OpenWith(nil) = %v, want ErrEnclaveDestroyed", err)
	}

	// And Open — the unbudgeted path — is unaffected: it has nothing to
	// refuse, so it never reports this error.
	o, err := v.Open()
	if err != nil {
		t.Fatalf("Open after a refused OpenWith: %v", err)
	}
	o.Destroy()
}

// TestSealedEnclave_OpenAllocatesOutsideAnyBudget pins the deliberate
// asymmetry, which is a contract and not an oversight: Open keeps working for
// callers that do not budget, and it does so by allocating unadmitted.
//
// It is here so that a future change routing Open through some ambient
// allocator has to come past a test that names the behavior, rather than
// quietly altering what Open's documentation promises.
func TestSealedEnclave_OpenAllocatesOutsideAnyBudget(t *testing.T) {
	v := sealForBudgetTest(t)

	a, err := NewAllocator(openBudget(8))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := v.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer e.Destroy()

	if got := a.InUse(); got != 0 {
		t.Errorf("an unrelated Allocator reports %d bytes in use after a plain Open, want 0", got)
	}
}

// TestSealedEnclave_OpenWithRefusesWhatTheBudgetCannotCover pins the refusal
// path and, more importantly, what a refusal COSTS: nothing. The sealed value
// survives a budget refusal intact and opens afterwards, so a tight budget is
// backpressure rather than a lost credential.
func TestSealedEnclave_OpenWithRefusesWhatTheBudgetCannotCover(t *testing.T) {
	v := sealForBudgetTest(t)

	// A sub-page budget: it constructs successfully and admits nothing, since
	// every enclave costs a whole page. That is the documented behavior of a
	// budget sized in the sizes of things rather than in pages, and it is the
	// cheapest way to reach the refusal without depending on a page size.
	a, err := NewAllocator(1)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := v.OpenWith(a)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("OpenWith under a sub-page budget = %v, want ErrBudgetExhausted", err)
	}
	if e != nil {
		t.Error("a refused OpenWith returned an enclave")
		e.Destroy()
	}

	// A BudgetError carries the figures, and they must be the page-rounded
	// ones the kernel charges rather than the sizes asked for.
	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("the refusal is not a *BudgetError: %v", err)
	}
	if be.Limit != 1 {
		t.Errorf("BudgetError.Limit = %d, want 1", be.Limit)
	}
	if be.Requested != LockedSize(len(sealedMaterial)) {
		t.Errorf("BudgetError.Requested = %d, want %d: the figures are the page-rounded ones the "+
			"kernel charges, not the size asked for", be.Requested, LockedSize(len(sealedMaterial)))
	}

	// Nothing was left reserved by the refusal.
	if got := a.InUse(); got != 0 {
		t.Errorf("a refused OpenWith left %d bytes reserved, want 0", got)
	}

	// The value is untouched: the refusal was about the budget, not about it.
	o, err := v.Open()
	if err != nil {
		t.Fatalf("Open after a budget refusal: %v (a refusal must not consume the value)", err)
	}
	if !o.EqualTo(sealedMaterial) {
		t.Error("the material changed across a budget refusal")
	}
	o.Destroy()

	// And a budget that CAN cover the open admits it, so the refusal above was
	// the budget's doing and not a value that never opened.
	roomy, err := NewAllocator(openBudget(4))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e2, err := v.OpenWith(roomy)
	if err != nil {
		t.Fatalf("OpenWith under a four-page budget: %v", err)
	}
	e2.Destroy()
}

// TestSealedEnclave_OpenWithGatesOnTheDestination pins the ORDER, which is
// what bounds the locked memory the budget does not itself charge.
//
// The destination is the one admitted allocation and it is taken FIRST, so an
// open the budget refuses has allocated no locked memory and has not touched a
// key. If the DEK were allocated first — the order this path had before
// budgets existed — a flood of opens would each take an unadmitted locked page
// BEFORE meeting the budget, which is the unbounded consumption an Allocator
// exists to stop.
//
// The instrument is the provider's Unprotect count, because the DEK's
// allocation is not observable after the fact but the key work that FOLLOWS it
// is: the DEK is allocated immediately before unprotect and nowhere else, so
// zero unprotects on a refused open means the refusal came first.
func TestSealedEnclave_OpenWithGatesOnTheDestination(t *testing.T) {
	kp := newMapKeyProtector()
	s, err := NewSealer(WithProvider(kp), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	// Three pages of material, so a one-page budget cannot cover the
	// destination and the refusal is unambiguous.
	page := LockedSize(1)
	material := bytes.Repeat([]byte{0x5B}, int(3*page))
	v, err := s.Seal(append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	tooSmall, err := NewAllocator(page)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	beforeUnprotects, beforeLedger := kp.unprotectCount(), liveCount()

	e, err := v.OpenWith(tooSmall)
	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("OpenWith under a one-page budget = %v, want a *BudgetError", err)
	}
	if e != nil {
		e.Destroy()
	}

	// The refusal named the DESTINATION, so that is what was reserved first.
	if be.Requested != LockedSize(len(material)) {
		t.Errorf("the refused reservation asked for %d bytes, want %d (the destination). "+
			"A key-page figure here would mean something was reserved ahead of the gate",
			be.Requested, LockedSize(len(material)))
	}
	// And nothing beyond the gate ran.
	if got := kp.unprotectCount() - beforeUnprotects; got != 0 {
		t.Errorf("a budget-refused open called Unprotect %d time(s), want 0: the DEK is allocated "+
			"immediately before that call, so this means a locked page was taken before the budget "+
			"was consulted", got)
	}
	if got := liveCount(); got != beforeLedger {
		t.Errorf("a budget-refused open left the ledger at %d, was %d: it allocated locked memory "+
			"it should never have reached", got, beforeLedger)
	}

	// Non-vacuity, and the single-reservation property in one number: a budget
	// of EXACTLY the destination admits the open. Charging the DEK as a second
	// reservation would refuse this, so the two halves of this test also pin
	// that an open costs the budget one reservation and not two.
	exact, err := NewAllocator(LockedSize(len(material)))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	admitted, err := v.OpenWith(exact)
	if err != nil {
		t.Fatalf("OpenWith under a budget of exactly one destination = %v, want success: an open "+
			"takes ONE reservation, so this is the smallest budget that serves it", err)
	}
	if !admitted.EqualTo(material) {
		t.Error("the admitted open returned the wrong material")
	}
	if got, want := exact.InUse(), LockedSize(len(material)); got != want {
		t.Errorf("the admitted open holds %d bytes, want %d", got, want)
	}
	if got := kp.unprotectCount() - beforeUnprotects; got != 1 {
		t.Errorf("the admitted open called Unprotect %d time(s), want 1; the refused one above "+
			"contributed none, which is what makes its zero meaningful", got)
	}
	admitted.Destroy()
}

// TestSealedEnclave_OpenWithConcurrentCallersDoNotStarveEachOther is the
// regression test for the design this method does NOT use.
//
// An earlier revision charged the transient key page as a SECOND reservation.
// It was more accurate and it broke under exactly the load an Allocator exists
// for: two callers sharing a budget sized for one open could each take a key
// page and then both be refused for the destination — a budget that could
// serve one open serving none. Here, many goroutines share a budget sized for
// ONE open, and the property is that somebody wins. Under two reservations per
// open this test fails intermittently; under one it cannot fail at all.
func TestSealedEnclave_OpenWithConcurrentCallersDoNotStarveEachOther(t *testing.T) {
	v := sealForBudgetTest(t)

	// Exactly one destination: every open but one must be refused, and one
	// must succeed.
	a, err := NewAllocator(LockedSize(len(sealedMaterial)))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	const rounds, goroutines = 20, 8
	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		opened := make(chan *MemoryEnclave, goroutines)
		refused := make(chan error, goroutines)
		start := make(chan struct{})

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				e, err := v.OpenWith(a)
				if err != nil {
					refused <- err
					return
				}
				opened <- e
			}()
		}
		close(start)
		wg.Wait()
		close(opened)
		close(refused)

		wins := 0
		for e := range opened {
			wins++
			if !e.EqualTo(sealedMaterial) {
				t.Fatal("a concurrent open returned the wrong material")
			}
			e.Destroy()
		}
		for err := range refused {
			if !errors.Is(err, ErrBudgetExhausted) {
				t.Fatalf("a refused open reported %v, want ErrBudgetExhausted", err)
			}
		}
		if wins == 0 {
			t.Fatalf("round %d: all %d concurrent opens were refused under a budget sized for one. "+
				"That is the fragmentation failure a second reservation per open causes: callers "+
				"take a transient page each and then none of them can afford a destination", round, goroutines)
		}
		if got := a.InUse(); got != 0 {
			t.Fatalf("round %d left %d bytes reserved, want 0", round, got)
		}
	}
}

// TestSealedEnclave_OpenWithOnARetiredGeneration covers the open path with the
// most locked memory in flight: a value sealed under a retired KEK generation
// materializes that generation's key for a single unwrap, on top of the DEK.
//
// Both are transient and neither is charged, so the budget the caller needs is
// still one destination — which is the claim being pinned. What the caller
// gives up for that is stated on OpenWith: the process peak exceeds the budget
// by up to two pages while this open is in flight.
func TestSealedEnclave_OpenWithOnARetiredGeneration(t *testing.T) {
	short := []byte("short-credential")

	s, err := NewSealer() // software provider, ModeRootKey
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(append([]byte(nil), short...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	s.mu.RLock()
	genBefore := s.kekGen
	s.mu.RUnlock()

	// Force the rotation, exactly as TestSealer_KEKRotatesAtTheMessageLimit
	// does: park the counter at the bound and seal past it.
	s.kekUsed.Store(kekMessageLimit)
	throwaway, err := s.Seal(append([]byte(nil), short...))
	if err != nil {
		t.Fatalf("Seal past the message limit: %v", err)
	}
	defer throwaway.Destroy()

	s.mu.RLock()
	genAfter := s.kekGen
	s.mu.RUnlock()
	if genAfter == genBefore {
		t.Fatalf("the KEK did not rotate (generation still %d); this test needs a retired "+
			"generation to exercise the unwrap path", genBefore)
	}

	// One destination, and that is all it takes — rotation must never strand a
	// value, and it must not silently raise what a caller has to budget either.
	a, err := NewAllocator(LockedSize(len(short)))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := v.OpenWith(a)
	if err != nil {
		t.Fatalf("OpenWith on a retired-generation value under a one-destination budget: %v", err)
	}
	if !e.EqualTo(short) {
		t.Error("the retired-generation value opened to the wrong material")
	}
	if got, want := a.InUse(), LockedSize(len(short)); got != want {
		t.Errorf("after the open the Allocator holds %d bytes, want %d", got, want)
	}
	e.Destroy()
	if got := a.InUse(); got != 0 {
		t.Errorf("after Destroy the Allocator holds %d bytes, want 0", got)
	}
}

// TestSealedEnclave_OpenWithIsConcurrencySafe runs the admitted open from many
// goroutines against one budget. Under -race it is the oracle for the new
// parameter threaded through the sealer's open path; without it, it still
// proves the accounting balances — every reservation taken is returned, so the
// budget lands back at zero rather than drifting up by a page per open.
func TestSealedEnclave_OpenWithIsConcurrencySafe(t *testing.T) {
	v := sealForBudgetTest(t)

	const goroutines = 16
	a, err := NewAllocator(openBudget(int64(goroutines) * 4))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, err := v.OpenWith(a)
			if err != nil {
				errs <- err
				return
			}
			if !e.EqualTo(sealedMaterial) {
				errs <- errors.New("concurrent OpenWith returned the wrong material")
			}
			e.Destroy()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if got := a.InUse(); got != 0 {
		t.Errorf("after %d concurrent opens and destroys the Allocator holds %d bytes, want 0", goroutines, got)
	}
}

// TestSealedEnclave_OpenWithOnADestroyedValue keeps the lifecycle answer the
// same on both entry points: a destroyed value is destroyed whichever way it
// is opened, and the refusal costs the budget nothing.
func TestSealedEnclave_OpenWithOnADestroyedValue(t *testing.T) {
	v := sealForBudgetTest(t)
	v.Destroy()

	a, err := NewAllocator(openBudget(8))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if _, err := v.OpenWith(a); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("OpenWith on a destroyed value = %v, want ErrEnclaveDestroyed", err)
	}
	if got := a.InUse(); got != 0 {
		t.Errorf("a refused OpenWith reserved %d bytes, want 0", got)
	}

	var nilValue *SealedEnclave
	if _, err := nilValue.OpenWith(a); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("(*SealedEnclave)(nil).OpenWith = %v, want ErrEnclaveDestroyed", err)
	}
}

// TestSealedEnclave_OpenWithPerOperationMode pins that the budget reaches the
// other mode too. ModePerOperation's unprotect allocates nothing itself, so
// what this proves is that the DEK and the destination are still admitted when
// a device — not an in-process hierarchy — supplies the key.
func TestSealedEnclave_OpenWithPerOperationMode(t *testing.T) {
	s, err := NewSealer(WithProvider(newMapKeyProtector()), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	a, err := NewAllocator(openBudget(8))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := v.OpenWith(a)
	if err != nil {
		t.Fatalf("OpenWith in ModePerOperation: %v", err)
	}
	if !e.EqualTo(sealedMaterial) {
		t.Error("opened to the wrong material")
	}
	if got, want := a.InUse(), LockedSize(len(sealedMaterial)); got != want {
		t.Errorf("after OpenWith the Allocator holds %d bytes, want %d", got, want)
	}
	e.Destroy()
	if got := a.InUse(); got != 0 {
		t.Errorf("after Destroy the Allocator holds %d bytes, want 0", got)
	}
}

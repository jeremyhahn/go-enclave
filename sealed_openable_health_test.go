// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"context"
	"crypto/rand"
	"errors"
	"runtime"
	"sync"
	"testing"
)

// enclaveBackedProtector is the provider shape that made the opt-in necessary:
// an OUT-OF-PACKAGE KeyProtector keeping its key in this process's locked
// memory. It deliberately does not implement the unexported sealHealth
// interface — no external package can, which is the defect — so it stands in
// for a real third-party provider exactly.
type enclaveBackedProtector struct{ key *MemoryEnclave }

func newEnclaveBackedProtector(t *testing.T) *enclaveBackedProtector {
	t.Helper()
	k, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	return &enclaveBackedProtector{key: k}
}

func (p *enclaveBackedProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return sealWithKey(p.key, key, nil)
}

func (p *enclaveBackedProtector) Unprotect(ctx context.Context, blob []byte, key []byte) error {
	return openWithKeyInto(p.key, blob, nil, key)
}

// health is what the provider author would pass to WithProviderHealth.
func (p *enclaveBackedProtector) health() error {
	if !p.key.IsAlive() {
		return ErrSealerWiped
	}
	return nil
}

// TestSealedEnclave_OpenableClosesTheExternalProviderFailOpen is the
// regression this pair of changes exists for.
//
// Before it, an external provider keeping its key in this process's memory got
// a confident nil from Openable after a WipeAll destroyed that key — a
// fail-open in a health API. Worse, the caller's actual Open then failed with
// ErrEnclaveDestroyed rather than ErrSealerWiped, which is the exact
// diagnostic misattribution this issue's own reasoning argues against.
func TestSealedEnclave_OpenableClosesTheExternalProviderFailOpen(t *testing.T) {
	p := newEnclaveBackedProtector(t)

	// The premise, asserted rather than assumed: this provider is invisible to
	// the in-package health seam. If it ever stops being so, this test is
	// measuring something else and must be rewritten, not deleted.
	if _, ok := interface{}(p).(sealHealth); ok {
		t.Fatal("provider satisfies sealHealth; it no longer stands in for an external one")
	}

	s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	// Non-vacuity: openable BEFORE the sweep. Without this the assertion below
	// would also pass for a value that was never openable at all.
	if err := v.Openable(); err != nil {
		t.Fatalf("Openable before the sweep = %v, want nil", err)
	}

	sweepForOpenableTest(t)

	// The value genuinely cannot be opened now — the provider's key was on the
	// ledger and the sweep took it. Established first so the Openable
	// assertion is about a real condition.
	if _, err := v.Open(t.Context()); err == nil {
		t.Fatal("Open succeeded after the sweep; this provider's key was supposed to be swept, " +
			"so the fail-open this test guards cannot arise and the test proves nothing")
	}

	if err := v.Openable(); err == nil {
		t.Error("Openable returned nil for a value that cannot be opened: an external provider " +
			"cannot implement the unexported health seam, and assuming it healthy is the " +
			"fail-open this change closes")
	} else if !errors.Is(err, ErrOpenabilityUnknown) {
		t.Errorf("Openable after the sweep = %v, want ErrOpenabilityUnknown: this package cannot "+
			"know whether the sweep took what this provider needed, and must say so rather "+
			"than guess either way", err)
	}
}

// TestSealedEnclave_OpenableBelievesAProviderThatReports pins the precedence:
// an explicit answer is authoritative and TERMINAL, and the sweep-generation
// fallback does not get to override it.
//
// If the fallback applied on top, a provider supplying a health report could
// never return nil after a sweep — its considered "the device still holds this
// key" would be overwritten with "I cannot tell", which is the one thing the
// report exists to say.
func TestSealedEnclave_OpenableBelievesAProviderThatReports(t *testing.T) {
	t.Run("reportsHealthyAfterASweep", func(t *testing.T) {
		s, err := NewSealer(
			WithProvider(newMapKeyProtector()),
			WithMode(ModePerOperation),
			WithProviderHealth(func() error { return nil }),
		)
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweepForOpenableTest(t)

		if err := v.Openable(); err != nil {
			t.Errorf("Openable = %v, want nil: the provider reported healthy and its answer is "+
				"authoritative; the generation fallback must not second-guess it", err)
		}
		// And the report agrees with reality, which is what makes believing it
		// defensible rather than merely convenient.
		e, err := v.Open(t.Context())
		if err != nil {
			t.Fatalf("Open = %v, but the provider reported healthy; one of the two is wrong", err)
		}
		e.Destroy()
	})

	t.Run("reportsWipedAfterASweep", func(t *testing.T) {
		p := newEnclaveBackedProtector(t)
		s, err := NewSealer(
			WithProvider(p), WithMode(ModePerOperation),
			WithProviderHealth(p.health),
		)
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		if err := v.Openable(); err != nil {
			t.Fatalf("Openable before the sweep = %v, want nil", err)
		}

		sweepForOpenableTest(t)

		// The PRECISE answer, not the fallback: a provider that can tell the
		// difference reports ErrSealerWiped, and the caller learns what
		// actually happened instead of that we could not tell.
		if err := v.Openable(); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Openable = %v, want ErrSealerWiped: an opted-in provider that knows its key "+
				"was destroyed must report it, not fall back to ErrOpenabilityUnknown", err)
		}
		if errors.Is(v.Openable(), ErrOpenabilityUnknown) {
			t.Error("an opted-in provider's precise answer was replaced by the fallback")
		}
	})
}

// TestSealedEnclave_OpenableUnknownOnlyAfterASweep pins the half of the design
// that distinguishes it from simply refusing to answer.
//
// A permanent "unknown" would be no better than the fail-open it replaces: it
// would read the same before and after a sweep, and so could never report the
// one event it exists to report.
func TestSealedEnclave_OpenableUnknownOnlyAfterASweep(t *testing.T) {
	p := newEnclaveBackedProtector(t)
	s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	// No sweep has run. The value demonstrably opens, so nil is the TRUE
	// answer and anything else is a false alarm on the common path.
	if err := v.Openable(); err != nil {
		t.Errorf("Openable with no sweep = %v, want nil: this value opens right now, and an "+
			"answer that never says so is not honesty", err)
	}
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("control: Open failed, so nil above was not the true answer: %v", err)
	}
	e.Destroy()

	sweepForOpenableTest(t)

	// Only now does it become unknown. The answer CHANGED, which is what makes
	// it a signal rather than a shrug.
	if err := v.Openable(); !errors.Is(err, ErrOpenabilityUnknown) {
		t.Errorf("Openable after the sweep = %v, want ErrOpenabilityUnknown", err)
	}
}

// TestSealedEnclave_OpenableGenerationDoesNotAffectModeRootKey pins that the
// fallback is scoped to the mode that needs it.
//
// In ModeRootKey the hierarchy is this package's own enclaves and it inspects
// them directly, so a nil there is KNOWLEDGE, not ignorance, and a sweep that
// provably did not take them must not downgrade it.
func TestSealedEnclave_OpenableGenerationDoesNotAffectModeRootKey(t *testing.T) {
	// Bump the generation before sealing so a value exists that was sealed
	// under an older generation than the current one — the precondition the
	// fallback triggers on — without wiping this sealer's own hierarchy.
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	// TWO, not one: the sequence's parity is an invariant of the whole process
	// — even means quiescent — and a real sweep bumps twice. Adding one here
	// would leave it permanently odd and mark every value sealed by every
	// LATER test as having overlapped a sweep. Measured: it did exactly that,
	// and was caught by the parity control in
	// TestSealedEnclave_OpenableSuspectsASealThatOverlappedASweep rather than
	// by this test, which passed either way.
	sweepGen.Add(2) // a completed sweep elsewhere; this sealer's hierarchy is untouched

	if got := sweepGeneration(); got == v.sealedAtGen {
		t.Fatal("the generation did not advance, so this test's precondition does not hold")
	}
	if err := v.Openable(); err != nil {
		t.Errorf("Openable = %v, want nil: ModeRootKey's hierarchy is in-process and was "+
			"inspected directly, so its nil is knowledge and the generation fallback must "+
			"not override it", err)
	}
}

// TestWipeAll_BumpsTheGenerationBeforeDestroying is the ordering test.
//
// The statement order in WipeAll is load-bearing and invisible: bump then
// destroy leaves at worst a brief false "unknown" while a sweep is in flight,
// which is safe; destroy then bump leaves a window in which the keys are gone
// and the generation still reads old, so Openable returns nil about a value
// that can no longer be opened — the fail-open, narrowed to a race that only
// appears under load.
//
// Reading the source cannot prove the order survives a later edit, so this
// PARKS inside the window and observes it from outside, the same way the
// allocator's retune test parks the withdrawal.
func TestWipeAll_BumpsTheGenerationBeforeDestroying(t *testing.T) {
	freshProcessSealer(t)

	e, err := NewMemoryEnclaveCopy([]byte("material that the sweep will destroy"))
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}

	before := sweepGeneration()

	var (
		mu           sync.Mutex
		genInWindow  uint64
		aliveInWndow bool
		parked       bool
	)

	sweepParkedForTest = func() {
		mu.Lock()
		defer mu.Unlock()
		parked = true
		genInWindow = sweepGeneration()
		aliveInWndow = e.IsAlive()
	}
	t.Cleanup(func() { sweepParkedForTest = nil })

	if _, err := WipeAll(context.Background()); err != nil {
		t.Fatalf("WipeAll: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Instrument validation: a seam that never fired would make every
	// assertion below vacuously true.
	if !parked {
		t.Fatal("the park seam never ran, so this test observed nothing")
	}
	if !aliveInWndow {
		t.Fatal("the enclave was already destroyed when the seam ran, so the seam is not " +
			"inside the window it claims to be and proves nothing about the order")
	}
	if genInWindow != before+1 {
		t.Errorf("inside the window the generation is %d, want %d (before=%d): the bump must "+
			"happen BEFORE anything is destroyed, or a value sealed earlier reads as "+
			"openable while its keys are already gone", genInWindow, before+1, before)
	}
}

// TestWipeAll_GenerationIsMonotonicAcrossSweeps pins that the counter is not
// reset. A reset would let a value sealed later read as older than one sealed
// earlier, which is the single thing the comparison must never do.
func TestWipeAll_GenerationIsMonotonicAcrossSweeps(t *testing.T) {
	freshProcessSealer(t)

	seen := make([]uint64, 0, 3)
	for i := 0; i < 3; i++ {
		if _, err := WipeAll(context.Background()); err != nil {
			t.Fatalf("WipeAll %d: %v", i, err)
		}
		seen = append(seen, sweepGeneration())
		freshProcessSealer(t)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Errorf("generation went %d -> %d; it must strictly increase", seen[i-1], seen[i])
		}
	}
}

// TestSealedEnclave_OpenableSuspectsASealThatOverlappedASweep closes the race a
// plain counter cannot see, found by review of the first implementation.
//
// A Seal that runs while WipeAll is midway through would, with a counter read
// after the seal, record the already-bumped number, later compare equal to it,
// and report nil about material the rest of that same sweep went on to destroy.
// The sequence's PARITY is what carries "a sweep was in flight when this was
// sealed", and this test seals inside the window to prove it.
func TestSealedEnclave_OpenableSuspectsASealThatOverlappedASweep(t *testing.T) {
	freshProcessSealer(t)

	p := newEnclaveBackedProtector(t)
	s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	var (
		mu               sync.Mutex
		v                *SealedEnclave
		sealErr          error
		parked           bool
		genAtSeal        uint64
		openableInWindow error
	)

	// Seal from INSIDE the sweep window, between the bump and the destruction.
	sweepParkedForTest = func() {
		mu.Lock()
		defer mu.Unlock()
		parked = true
		genAtSeal = sweepGeneration()
		v, sealErr = s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))

		// Asked INSIDE the window, which is the only place the parity is
		// load-bearing. Out here the count still reads equal to what the seal
		// just recorded — the balancing bump has not happened yet — so a
		// count comparison alone answers "nothing has changed, it is fine"
		// about a value whose key this very sweep is about to destroy. Only
		// the odd generation records that a sweep was underway.
		if sealErr == nil {
			openableInWindow = v.Openable()
		}
	}
	t.Cleanup(func() { sweepParkedForTest = nil })

	if _, err := WipeAll(context.Background()); err != nil {
		t.Fatalf("WipeAll: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !parked {
		t.Fatal("the park seam never ran; this test observed nothing")
	}
	if sealErr != nil {
		t.Skipf("the seal inside the sweep window failed (%v); the race this pins "+
			"needs a seal that SUCCEEDS mid-sweep", sealErr)
	}
	defer v.Destroy()

	// Instrument validation: the seal really did happen mid-sweep.
	if !sweepInFlight(genAtSeal) {
		t.Fatalf("the generation at seal time was %d, which is not odd, so the seal did not "+
			"overlap a sweep and this test proves nothing", genAtSeal)
	}

	// The assertion the parity exists for: inside the window the count had not
	// moved, so anything reading the count alone said "fine".
	if !errors.Is(openableInWindow, ErrOpenabilityUnknown) {
		t.Errorf("Openable INSIDE the sweep window = %v, want ErrOpenabilityUnknown: the "+
			"sequence still read equal to the value's own, so only its odd parity records "+
			"that a sweep was in flight and about to take this provider's key",
			openableInWindow)
	}

	// And it still reports unknown once the sweep has completed, where the
	// changed count is what carries it.
	if got := v.Openable(); !errors.Is(got, ErrOpenabilityUnknown) {
		t.Errorf("Openable for a value sealed mid-sweep = %v, want ErrOpenabilityUnknown: the "+
			"sequence reads equal at both ends, and only its parity records that a sweep "+
			"was in flight when this was sealed", got)
	}
}

// TestSealer_ProviderHealthIsIgnoredInRootKeyMode pins the option against its
// own documentation, which says it is ignored in [ModeRootKey].
//
// Without the mode gate a caller reusing one health callback across both modes
// gets the callback's error from a sealer whose root and KEK are demonstrably
// alive and whose Open succeeds — a provider callback overruling the
// authoritative in-process hierarchy.
func TestSealer_ProviderHealthIsIgnoredInRootKeyMode(t *testing.T) {
	freshProcessSealer(t)

	called := false
	s, err := NewSealer(WithProviderHealth(func() error {
		called = true
		return ErrSealerWiped
	}))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	if err := v.Openable(); err != nil {
		t.Errorf("Openable = %v, want nil: this sealer's own hierarchy is alive and "+
			"authoritative, and WithProviderHealth is documented as ignored in ModeRootKey", err)
	}
	if called {
		t.Error("the health callback was consulted in ModeRootKey, which its documentation " +
			"says it is not")
	}

	// The control that makes the nil above meaningful: the value really opens.
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open = %v; Openable said nil, so one of the two is wrong", err)
	}
	e.Destroy()
}

// TestWipeAll_ConcurrentSweepsKeepTheParityInvariant pins the SINGLE-WRITER
// requirement the sequence's parity depends on.
//
// The odd/even reading is a sequence lock, and a sequence lock is only valid
// with one writer. Two concurrent sweeps break it outright: the second one's
// opening bump takes the sequence from odd back to EVEN while both are still
// running, so a value sealed in that window records an even sequence, reads "no
// sweep was in flight", and can be reported openable after one of those sweeps
// has already destroyed the provider's key.
//
// The invariant asserted here is the one that must hold for the whole design:
// whenever a sweep is inside its own window, the sequence is ODD.
func TestWipeAll_ConcurrentSweepsKeepTheParityInvariant(t *testing.T) {
	freshProcessSealer(t)

	const sweepers = 8

	var (
		mu       sync.Mutex
		observed []uint64
	)
	sweepParkedForTest = func() {
		g := sweepGeneration()
		mu.Lock()
		observed = append(observed, g)
		mu.Unlock()
		// Widen the window so a second sweep, if it were able to start, would
		// have every chance to land its own bump inside this one.
		runtime.Gosched()
	}
	t.Cleanup(func() { sweepParkedForTest = nil })

	var wg sync.WaitGroup
	for i := 0; i < sweepers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := WipeAll(context.Background()); err != nil {
				t.Errorf("WipeAll: %v", err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	// Instrument validation: every sweep must have reached the window, or the
	// invariant below is asserted over fewer samples than it appears to be.
	if len(observed) != sweepers {
		t.Fatalf("the park seam fired %d times, want %d; this test did not observe what it "+
			"claims to", len(observed), sweepers)
	}
	for i, g := range observed {
		if !sweepInFlight(g) {
			t.Errorf("sweep %d observed sequence %d inside its own window, which is EVEN and "+
				"therefore reads as 'no sweep running'. Two sweeps overlapped and the "+
				"single-writer invariant the parity depends on is broken", i, g)
		}
	}
}

// deviceBackedInPackageProtector implements the IN-PACKAGE health seam and
// reports healthy unconditionally, standing in for a provider whose key lives
// outside this process. SoftwareProvider is the only real implementor of that
// seam and its root is destroyed by a sweep, so without this type there is no
// case where the sealHealth arm returns nil AFTER a sweep — and the precedence
// on that arm is therefore unobservable. Measured: a mutant applying the
// fallback on top of it survived the whole suite.
type deviceBackedInPackageProtector struct{ m map[string][]byte }

func newDeviceBackedInPackageProtector() *deviceBackedInPackageProtector {
	return &deviceBackedInPackageProtector{m: make(map[string][]byte)}
}

func (p *deviceBackedInPackageProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	blob := make([]byte, 16)
	if _, err := rand.Read(blob); err != nil {
		return nil, err
	}
	p.m[string(blob)] = append([]byte(nil), key...)
	return blob, nil
}

func (p *deviceBackedInPackageProtector) Unprotect(ctx context.Context, blob []byte, key []byte) error {
	stored, ok := p.m[string(blob)]
	if !ok || len(stored) != len(key) {
		return ErrSealedAuthentication
	}
	copy(key, stored)
	return nil
}

// openable implements sealHealth: the key is held outside this process's
// locked memory, so a sweep does not touch it.
func (p *deviceBackedInPackageProtector) openable() error { return nil }

// TestSealedEnclave_OpenableBelievesTheInPackageHealthSeam covers the arm the
// other precedence test cannot reach.
//
// Both arms of Sealer.openable return the provider's answer TERMINALLY, and the
// sweep-generation fallback must not be applied on top of either. The callback
// arm is covered by OpenableBelievesAProviderThatReports; this is the
// sealHealth arm, which no other test can exercise in the healthy-after-sweep
// state because SoftwareProvider — its only production implementor — always
// reports wiped after a sweep.
func TestSealedEnclave_OpenableBelievesTheInPackageHealthSeam(t *testing.T) {
	p := newDeviceBackedInPackageProtector()

	// The premise, asserted rather than assumed.
	if _, ok := interface{}(p).(sealHealth); !ok {
		t.Fatal("this provider does not implement sealHealth, so it exercises the wrong arm")
	}

	s, err := NewSealer(WithProvider(p), WithMode(ModePerOperation))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	sweepForOpenableTest(t)

	if err := v.Openable(); err != nil {
		t.Errorf("Openable after the sweep = %v, want nil: this provider reported healthy "+
			"through the in-package seam and its answer is terminal; the generation "+
			"fallback must not be applied on top of it", err)
	}
	// The control that makes the nil meaningful: the value really does open.
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open after the sweep = %v; Openable said nil, so one of the two is wrong", err)
	}
	if !e.EqualTo(sealedMaterial) {
		t.Error("post-sweep open returned the wrong material")
	}
	e.Destroy()
}

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
	"testing"
)

// sweepForOpenableTest runs a [WipeAll] the way a test in this file needs it:
// hermetic against the PROCESS sealer.
//
// A sweep is process-wide, so it destroys the lazily installed process sealer
// along with everything else — and that sealer is one-shot, so every later
// test calling [NewSealed] would get ErrSealerWiped from a sweep it never ran.
// Measured: without this, eleven tests in sealed_test.go fail, because the
// files here sort ahead of it.
//
// It composes [freshProcessSealer] rather than reaching for
// resetProcessSealerForTest itself. That helper is the package's ONE answer to
// process-sealer contamination, and a second spelling of it is how the two
// drift: the next refinement to hermeticity would land in one of them.
func sweepForOpenableTest(t *testing.T) {
	t.Helper()
	freshProcessSealer(t)
	sweep(t)
}

// TestSealedEnclave_OpenableReportsTheSweep is the resolution of #33: the
// sweep is NOT extended to sealed values, and what it leaves behind is
// reported by a question of its own instead.
//
// The defect it closes is a name collision, not a missing feature. #40 made
// [MemoryEnclave.IsAlive] report false once material is wiped, so across this
// package IsAlive now reads as "you can actually use this" — while
// SealedEnclave.IsAlive tests ciphertext presence, which a sweep does not
// touch. A swept value therefore reads alive and yields nothing usable, the
// exact shape #13 was about, and a doc comment is a weak fix for a name that
// means something else next door.
func TestSealedEnclave_OpenableReportsTheSweep(t *testing.T) {
	s, err := NewSealer() // software provider, ModeRootKey
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	// Non-vacuity: openable BEFORE the sweep, so what follows is the sweep's
	// doing and not a value that was never openable.
	if err := v.Openable(); err != nil {
		t.Fatalf("Openable before the sweep = %v, want nil", err)
	}
	e, err := v.Open()
	if err != nil {
		t.Fatalf("Open before the sweep: %v", err)
	}
	e.Destroy()

	sweepForOpenableTest(t)

	// IsAlive is UNCHANGED and that is deliberate: it reports on the
	// ciphertext, which is still here. Changing it would cost its cheap local
	// meaning and its lock profile to answer a different question.
	if !v.IsAlive() {
		t.Error("the sweep destroyed the SealedEnclave; the ledger holds MemoryEnclaves and this " +
			"type is not one. If that changed deliberately, WipeAll's contract, SealedEnclave's " +
			"documentation and the #33 decision all need updating")
	}

	// And Openable is the one that moved.
	if err := v.Openable(); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Openable after the sweep = %v, want ErrSealerWiped: a value that cannot be "+
			"opened must say so, or IsAlive is the only signal and it reports the wrong thing", err)
	}

	// It agrees with what an actual Open does, which is the property that
	// makes it worth calling at all.
	if _, err := v.Open(); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Open after the sweep = %v, want ErrSealerWiped", err)
	}
}

// TestSealedEnclave_OpenableSeparatesASweepFromADestroy pins the third ground
// for not sweeping sealed values: it would REGRESS diagnostics.
//
// A swept value that had been destroyed by the sweep would report
// ErrEnclaveDestroyed — "you destroyed this" — and send an operator hunting a
// lifecycle bug in their own code that does not exist. The two errors go to
// two different pieces of code, so they have to stay distinguishable.
func TestSealedEnclave_OpenableSeparatesASweepFromADestroy(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	swept, err := s.Seal(append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer swept.Destroy()

	destroyed, err := s.Seal(append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	destroyed.Destroy()

	sweepForOpenableTest(t)

	if err := swept.Openable(); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("a swept value reports %v, want ErrSealerWiped", err)
	}
	if err := destroyed.Openable(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("a destroyed value reports %v, want ErrEnclaveDestroyed", err)
	}
	if errors.Is(swept.Openable(), ErrEnclaveDestroyed) {
		t.Error("a swept value reports ErrEnclaveDestroyed; that reads as 'you destroyed this' " +
			"and sends an operator to the wrong code")
	}
}

// TestSealedEnclave_OpenableOnDestroyedAndNilValues covers the lifecycle
// answers, including the nil receiver every method on this type accepts.
func TestSealedEnclave_OpenableOnDestroyedAndNilValues(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if err := v.Openable(); err != nil {
		t.Fatalf("Openable on a live value = %v, want nil", err)
	}

	v.Destroy()
	if err := v.Openable(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Openable after Destroy = %v, want ErrEnclaveDestroyed", err)
	}
	// Idempotent, like every other method here.
	v.Destroy()
	if err := v.Openable(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Openable after a second Destroy = %v, want ErrEnclaveDestroyed", err)
	}

	var nilValue *SealedEnclave
	if err := nilValue.Openable(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("(*SealedEnclave)(nil).Openable() = %v, want ErrEnclaveDestroyed", err)
	}
}

// TestSealedEnclave_OpenableSplitsByMode is the second ground for not
// sweeping: sweeping sealed values would be WRONG, not merely costly.
//
// A [ModePerOperation] value backed by a device stays legitimately openable
// after a sweep — the device holds the key, and this process's memory never
// protected it — so destroying it on a sweep would destroy recoverable
// application data, under a call documented for sweep-and-keep-running
// callers. Openable has to report that honestly, which means nil.
//
// The software subtest is what stops that nil from being vacuous: the same
// mode with an in-process root DOES report the sweep, so the nil above is a
// judgment about where the key lives rather than a method that never fails.
func TestSealedEnclave_OpenableSplitsByMode(t *testing.T) {
	t.Run("deviceHeldKeySurvivesTheSweep", func(t *testing.T) {
		// The provider REPORTS its health, so its answer is authoritative and
		// the sweep-generation fallback must not override it. Without
		// WithProviderHealth this same value now reports
		// ErrOpenabilityUnknown — see reportsNothingAfterASweep below — and
		// the difference between the two subtests is the whole of what
		// opting in buys.
		s, err := NewSealer(
			WithProvider(newMapKeyProtector()),
			WithMode(ModePerOperation),
			WithProviderHealth(func() error { return nil }),
		)
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweepForOpenableTest(t)

		if err := v.Openable(); err != nil {
			t.Errorf("Openable after a sweep with a device-held key = %v, want nil: the device "+
				"still holds the key, the value still opens, and a provider that SAYS so must "+
				"not be second-guessed by the generation fallback", err)
		}
		// Openable's answer has to match reality, so open it and see.
		e, err := v.Open()
		if err != nil {
			t.Fatalf("Open after a sweep with a device-held key = %v; Openable said nil, so one "+
				"of the two is wrong", err)
		}
		if !e.EqualTo(sealedMaterial) {
			t.Error("post-sweep open returned the wrong material")
		}
		e.Destroy()
	})

	t.Run("softwareProviderRootDoesNot", func(t *testing.T) {
		s, err := NewSealer(WithProvider(NewSoftwareProvider()), WithMode(ModePerOperation))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		if err := v.Openable(); err != nil {
			t.Fatalf("Openable before the sweep = %v, want nil", err)
		}

		sweepForOpenableTest(t)

		// The software provider's root IS an in-process enclave, so this mode's
		// usual "the device survives" does not apply and Openable must not
		// claim it does. This is the assertion that would go red if the
		// provider were consulted only when it is hardware — or not at all.
		if err := v.Openable(); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Openable after the sweep = %v, want ErrSealerWiped: the software provider's "+
				"root is an in-process enclave and the sweep destroyed it", err)
		}
		if _, err := v.Open(); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Open after the sweep = %v, want ErrSealerWiped", err)
		}
	})
}

// TestSoftwareProvider_OpenableDoesNotGenerateARoot pins that asking the
// question is free of side effects. rootLocked generates on first use, and
// reusing it here would turn a diagnostic into a locked-memory allocation and
// a CSPRNG draw — for a provider that had sealed nothing.
func TestSoftwareProvider_OpenableDoesNotGenerateARoot(t *testing.T) {
	p := NewSoftwareProvider()

	if err := p.openable(); err != nil {
		t.Errorf("openable on a fresh provider = %v, want nil: nothing was sealed through it, "+
			"so nothing it holds is unopenable", err)
	}

	p.mu.Lock()
	root := p.root
	p.mu.Unlock()
	if root != nil {
		t.Error("asking whether a provider can open generated its root; a diagnostic must not " +
			"allocate locked memory or draw from the CSPRNG")
	}
}

// TestWipeAll_DoesNotSweepSealedEnclaves pins the FIRST ground for the #33
// decision, at the place the decision is actually observable: the count.
//
// WipeAll's count means "still holding locked memory," and that invariant is
// the whole value of the number. A SealedEnclave holds none — its envelope is
// heap ciphertext — so covering it would either corrupt the count or require a
// second one. This test is what a change extending the sweep would have to
// come past.
func TestWipeAll_DoesNotSweepSealedEnclaves(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	const n = 5
	values := make([]*SealedEnclave, 0, n)
	for i := 0; i < n; i++ {
		v, err := s.Seal(append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		defer v.Destroy()
		values = append(values, v)
	}

	// The sealed values are not on the ledger; the sealer's KEYS are, and they
	// are what the sweep is for.
	freshProcessSealer(t)

	if remaining := sweep(t); remaining != 0 {
		t.Fatalf("the sweep left %d enclave(s) holding locked memory; this test needs a clean "+
			"sweep to attribute the count below", remaining)
	}

	// A second sweep with n sealed values still live reports zero. If sealed
	// values were ever put on the ledger, this is the number that would break:
	// they hold no locked memory, so counting them would make the count mean
	// something else.
	if remaining := sweep(t); remaining != 0 {
		t.Errorf("with %d live sealed values the sweep counts %d, want 0: the count means "+
			"'still holding locked memory' and a SealedEnclave holds none", n, remaining)
	}
	if got := liveCount(); got != 0 {
		t.Errorf("the ledger holds %d entries after the sweep, want 0", got)
	}

	for i, v := range values {
		if !v.IsAlive() {
			t.Errorf("value %d was destroyed by the sweep", i)
		}
		if err := v.Openable(); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("value %d reports Openable = %v after the sweep, want ErrSealerWiped", i, err)
		}
	}
}

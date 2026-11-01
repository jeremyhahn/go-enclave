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
	"fmt"
	"sync"
	"testing"
)

// TestSealer_ProviderOptionSelectsTheMode pins that the provider option fixes
// the mode, and that two provider options are refused rather than resolved by
// order.
func TestNewSealer_ReturnsTheInterface(t *testing.T) {
	ctx := t.Context()
	p := newSoftwareProvider()
	t.Cleanup(func() { _ = p.Destroy() })

	ctors := map[string]struct {
		opts []SealerOption
		want Mode
	}{
		"default":          {nil, ModeRootKey},
		"WithRootUnsealer": {[]SealerOption{providerOption(p, ModeRootKey)}, ModeRootKey},
		"WithKeyProtector": {[]SealerOption{providerOption(p, ModePerOperation)}, ModePerOperation},
	}
	for name, tc := range ctors {
		t.Run(name, func(t *testing.T) {
			s, err := NewSealer(tc.opts...)
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			defer s.Destroy()
			if _, ok := s.(*envelopeSealer); !ok {
				t.Errorf("NewSealer returned a %T, want *envelopeSealer", s)
			}
			if got := s.Mode(); got != tc.want {
				t.Errorf("Mode() = %v, want %v", got, tc.want)
			}
			v, err := s.Seal(ctx, []byte("material"))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			defer v.Destroy()
			e, err := v.Open(ctx)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer e.Destroy()
			if !holds(e, []byte("material")) {
				t.Error("the opened enclave does not hold the material")
			}
		})
	}

	failing := map[string][]SealerOption{
		"nil option":     {nil},
		"two providers":  {providerOption(p, ModeRootKey), providerOption(p, ModePerOperation)},
		"rotation limit": {WithKEKRotationLimit(0)},
	}
	for name, opts := range failing {
		t.Run(name+"/failure", func(t *testing.T) {
			s, err := NewSealer(opts...)
			if err == nil {
				t.Fatal("err = nil, want a failure")
			}
			if s != nil {
				t.Errorf("NewSealer returned %#v on failure, want a nil interface", s)
			}
		})
	}
}

func TestSealer_ProviderOptionSelectsTheMode(t *testing.T) {
	for _, tc := range []struct {
		name string
		opt  SealerOption
		want Mode
	}{
		{"KeyProtector", WithKeyProtector(newMapKeyProtector(t)), ModePerOperation},
		{"RootUnsealer", WithRootUnsealer(&fixedRootUnsealer{fill: 0x42}), ModeRootKey},
		{"software as KeyProtector", WithKeyProtector(newSoftwareProvider()), ModePerOperation},
		{"software as RootUnsealer", WithRootUnsealer(newSoftwareProvider()), ModeRootKey},
	} {
		s, err := newEnvelopeSealer(tc.opt)
		if err != nil {
			t.Errorf("NewSealer(%s): %v", tc.name, err)
			continue
		}
		if s.Mode() != tc.want {
			t.Errorf("NewSealer(%s).Mode() = %v, want %v", tc.name, s.Mode(), tc.want)
		}
		if s.owned != nil {
			t.Errorf("NewSealer(%s) owns a provider it was given", tc.name)
		}
	}

	sp := newSoftwareProvider()
	for name, opts := range map[string][]SealerOption{
		"both":                 {WithKeyProtector(sp), WithRootUnsealer(sp)},
		"KeyProtector twice":   {WithKeyProtector(sp), WithKeyProtector(sp)},
		"RootUnsealer twice":   {WithRootUnsealer(sp), WithRootUnsealer(sp)},
		"nil after a live one": {WithRootUnsealer(sp), WithKeyProtector(nil)},
	} {
		if s, err := NewSealer(opts...); !errors.Is(err, ErrInvalidProvider) || s != nil {
			t.Errorf("NewSealer(%s) = (%v, %v), want (nil, ErrInvalidProvider)", name, s, err)
		}
	}
}

// TestSealer_DefaultIsSoftwareRootKey pins that no options means the
// pure-software provider in ModeRootKey, that it round trips, and that the
// process default NewSealed installs has the same shape.
func TestSealer_DefaultIsSoftwareRootKey(t *testing.T) {
	freshProcessSealer(t)
	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer(): %v", err)
	}
	if s.Mode() != ModeRootKey {
		t.Errorf("default Mode() = %v, want ModeRootKey", s.Mode())
	}

	want := []byte("default-sealer-round-trip-material")
	v, err := s.sealData(t.Context(), append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer e.Destroy()
	if !holds(e, want) {
		t.Error("default sealer round trip returned the wrong material")
	}

	p, err := newSealed(t.Context(), append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer p.Destroy()
	if got := p.sealer.Mode(); got != ModeRootKey {
		t.Errorf("process default sealer mode = %v, want ModeRootKey", got)
	}
}

// TestSealer_RefusesForeignProvider pins that a value sealed under one
// provider does not open under another, in either mode. The envelope is
// rebuilt against the second sealer directly, since normal use has no path
// for that misuse.
func TestSealer_RefusesForeignProvider(t *testing.T) {
	build := func(t *testing.T, m Mode) (*envelopeSealer, *envelopeSealer) {
		t.Helper()
		a, err := newEnvelopeSealer(providerOption(newSoftwareProvider(), m))
		if err != nil {
			t.Fatalf("NewSealer A: %v", err)
		}
		b, err := newEnvelopeSealer(providerOption(newSoftwareProvider(), m))
		if err != nil {
			t.Fatalf("NewSealer B: %v", err)
		}
		return a, b
	}

	for _, m := range []Mode{ModePerOperation, ModeRootKey} {
		t.Run(m.String(), func(t *testing.T) {
			a, b := build(t, m)

			want := []byte("cross-provider-material")
			v, err := a.sealData(t.Context(), append([]byte(nil), want...))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			defer v.Destroy()

			// Give B a live hierarchy of its own, so the refusal below is a key
			// mismatch and not "B never sealed anything".
			warm, err := b.sealData(t.Context(), []byte("warm-up"))
			if err != nil {
				t.Fatalf("warm-up Seal: %v", err)
			}
			defer warm.Destroy()

			foreign := &sealedValue{sealedState: &sealedState{sealer: b, sealed: v.sealed, blob: v.blob, size: v.size}}
			if e, err := foreign.Open(t.Context()); !errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("Open under a foreign provider = %v, want ErrSealedAuthentication", err)
				if e != nil {
					e.Destroy()
				}
			}

			// Control: the same envelope opens under its own sealer.
			e, err := v.Open(t.Context())
			if err != nil {
				t.Fatalf("Open under the sealing provider: %v", err)
			}
			if !holds(e, want) {
				t.Error("control open returned the wrong material")
			}
			e.Destroy()
		})
	}
}

// TestSealer_EnvelopeBindsBlobToCiphertext pins the AAD binding end to end.
// The map provider files an alias blob that recovers the exact DEK the value
// was sealed with, so the envelope differs only in the blob bytes; without
// the AAD binding it would open.
func TestSealer_EnvelopeBindsBlobToCiphertext(t *testing.T) {
	kp := newMapKeyProtector(t)
	s, err := newEnvelopeSealer(WithKeyProtector(kp))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	want := []byte("blob-binding-material")
	v, err := s.sealData(t.Context(), append([]byte(nil), want...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	aliasBlob := []byte("map-key-protector-alias-blob")
	if !kp.alias(v.blob, aliasBlob) {
		t.Fatal("could not alias the sealed value's blob; the fake provider does not hold it")
	}

	// Setup sanity: the alias must recover the same DEK, or the refusal below
	// would be a key mismatch. Compared inside locked borrows, never copied to
	// the heap.
	dekA, err := newMemorySized(dekBytes)
	if err != nil {
		t.Fatalf("allocating dekA: %v", err)
	}
	defer func() { _ = dekA.Destroy() }()
	dekB, err := newMemorySized(dekBytes)
	if err != nil {
		t.Fatalf("allocating dekB: %v", err)
	}
	defer func() { _ = dekB.Destroy() }()
	same := false
	if err := dekA.WithBytes(func(a []byte) error {
		if err := kp.Unprotect(t.Context(), v.blob, a); err != nil {
			return fmt.Errorf("Unprotect(original): %w", err)
		}
		return dekB.WithBytes(func(b []byte) error {
			if err := kp.Unprotect(t.Context(), aliasBlob, b); err != nil {
				return fmt.Errorf("Unprotect(alias): %w", err)
			}
			same = bytes.Equal(a, b)
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
	if !same {
		t.Fatal("the alias blob recovers a different DEK; the test setup is broken")
	}

	repaired := &sealedValue{sealedState: &sealedState{sealer: s, sealed: v.sealed, blob: aliasBlob, size: v.size}}
	if e, err := repaired.Open(t.Context()); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Open with a re-paired (valid, same-DEK) blob = %v, want ErrSealedAuthentication: "+
			"the ciphertext is not bound to the exact blob it was sealed with", err)
		if e != nil {
			e.Destroy()
		}
	}

	// Control: untouched, the value opens.
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("control Open: %v", err)
	}
	if !holds(e, want) {
		t.Error("control open returned the wrong material")
	}
	e.Destroy()
}

// TestSealer_WipedFailsClosedPerMode pins the mode asymmetry around a
// shutdown sweep:
//
//   - ModeRootKey: the hierarchy is swept; new seals and existing values
//     report ErrSealerWiped, and the sealer never re-keys.
//   - ModePerOperation over the in-process software provider: the same, from
//     the provider's side.
//   - ModePerOperation over a device-held key (the map provider): the sweep
//     destroys nothing the values depend on, so sealing and opening keep
//     working.
func TestSealer_WipedFailsClosedPerMode(t *testing.T) {
	material := []byte("mode-asymmetry-material")

	t.Run("ModeRootKey", func(t *testing.T) {
		s, err := newEnvelopeSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.sealData(t.Context(), append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweep(t)

		if _, err := v.Open(t.Context()); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Open after sweep = %v, want ErrSealerWiped", err)
		}
		if _, err := s.sealData(t.Context(), append([]byte(nil), material...)); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Seal after sweep = %v, want ErrSealerWiped: the sealer must fail closed, never re-key", err)
		}
	})

	t.Run("ModePerOperation_software", func(t *testing.T) {
		s, err := newEnvelopeSealer(WithKeyProtector(newSoftwareProvider()))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.sealData(t.Context(), append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweep(t)

		if _, err := v.Open(t.Context()); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Open after sweep = %v, want ErrSealerWiped", err)
		}
		if _, err := s.sealData(t.Context(), append([]byte(nil), material...)); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Seal after sweep = %v, want ErrSealerWiped", err)
		}
	})

	t.Run("ModePerOperation_deviceHeld", func(t *testing.T) {
		s, err := newEnvelopeSealer(WithKeyProtector(newMapKeyProtector(t)))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.sealData(t.Context(), append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweep(t)

		// The device still holds the keys: existing values open and new seals
		// work, because nothing in this process's memory protected the DEKs.
		e, err := v.Open(t.Context())
		if err != nil {
			t.Fatalf("Open after sweep with a device-held key = %v; "+
				"a sweep must not invalidate values whose keys the process never held", err)
		}
		if !holds(e, material) {
			t.Error("post-sweep open returned the wrong material")
		}
		e.Destroy()

		fresh, err := s.sealData(t.Context(), append([]byte(nil), material...))
		if err != nil {
			t.Fatalf("Seal after sweep with a device-held key: %v", err)
		}
		fresh.Destroy()
	})
}

// TestSealer_ProviderErrorsSurfaceHonestly pins the error shaping on both
// paths: a provider's own failure surfaces under ErrSealFailed on seal and
// ErrOpenFailed on open, with the cause reachable, and is never reported as
// an authentication failure.
func TestSealer_ProviderErrorsSurfaceHonestly(t *testing.T) {
	deviceDown := errors.New("device unreachable: session pool exhausted")
	s, err := newEnvelopeSealer(WithKeyProtector(&erroringProvider{err: deviceDown}))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	_, err = s.sealData(t.Context(), []byte("provider-error-material"))
	if !errors.Is(err, ErrSealFailed) {
		t.Errorf("Seal with a failing provider = %v, want it to match ErrSealFailed", err)
	}
	if !errors.Is(err, deviceDown) {
		t.Errorf("Seal error %v does not preserve the provider's cause", err)
	}
	if errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Seal error %v reads as an authentication failure; an infrastructure fault must not", err)
	}

	// The open path: seal under a healthy provider, open under one that
	// fails with its own error. The sealer must keep that error reachable and
	// join it under ErrOpenFailed — the open-side "could not", never a
	// forgery verdict.
	kp := newMapKeyProtector(t)
	healthy, err := newEnvelopeSealer(WithKeyProtector(kp))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := healthy.sealData(t.Context(), []byte("provider-error-material"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	v.sealer = s // the erroring provider now answers this value's opens
	_, err = v.Open(t.Context())
	if !errors.Is(err, deviceDown) {
		t.Errorf("Open with a failing provider = %v, want the provider's own error to surface", err)
	}
	if !errors.Is(err, ErrOpenFailed) {
		t.Errorf("Open with a failing provider = %v, want it to match ErrOpenFailed", err)
	}
	if errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("Open error %v reads as an authentication failure; an operator would hunt an attacker who does not exist", err)
	}
	v.sealer = healthy

	// A provider returning an empty blob is a contract violation caught at
	// seal time, not at the first failed open months later.
	eb, err := newEnvelopeSealer(WithKeyProtector(emptyBlobProtector{}))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := eb.sealData(t.Context(), []byte("empty-blob-material")); !errors.Is(err, ErrSealFailed) {
		t.Errorf("Seal with an empty-blob provider = %v, want ErrSealFailed", err)
	}
}

// TestSealer_SetSealerIsOneShot pins the installation contract: the first
// install wins, the lazy default counts as an install, and NewSealed routes
// through the installed sealer (counted by its provider's operations).
func TestSealer_SetSealerIsOneShot(t *testing.T) {
	resetProcessSealerForTest()
	t.Cleanup(resetProcessSealerForTest)

	if err := SetSealer(nil); !errors.Is(err, ErrNilSealer) {
		t.Errorf("SetSealer(nil) = %v, want ErrNilSealer", err)
	}

	kp := newMapKeyProtector(t)
	own, err := newEnvelopeSealer(WithKeyProtector(kp))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if err := SetSealer(own); err != nil {
		t.Fatalf("SetSealer: %v", err)
	}

	// The second install fails closed whatever it carries.
	other, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if err := SetSealer(other); !errors.Is(err, ErrSealerInstalled) {
		t.Errorf("second SetSealer = %v, want ErrSealerInstalled", err)
	}

	// NewSealed routes through the installed sealer: the provider's Protect
	// count moves.
	before := kp.protectCount()
	v, err := newSealed(t.Context(), []byte("routed-material"))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer v.Destroy()
	if got := kp.protectCount(); got != before+1 {
		t.Errorf("installed provider saw %d Protects, want %d: NewSealed did not route through the installed sealer", got, before+1)
	}

	// A stray early seal locks the configuration: after the lazy default is
	// installed, SetSealer fails closed.
	resetProcessSealerForTest()
	if _, err := newSealed(t.Context(), []byte("stray-early-seal")); err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	if err := SetSealer(own); !errors.Is(err, ErrSealerInstalled) {
		t.Errorf("SetSealer after a lazy default = %v, want ErrSealerInstalled", err)
	}
}

// TestSealer_NilReceiver pins the nil contract: a nil *envelopeSealer refuses with a
// typed error AND still honors the ownership contract on the caller's slice —
// losing your sealer must not mean leaving the material behind.
func TestSealer_NilReceiver(t *testing.T) {
	data := append([]byte(nil), sealedMaterial...)
	var s *envelopeSealer
	if _, err := s.sealData(t.Context(), data); !errors.Is(err, ErrNilSealer) {
		t.Errorf("nil Sealer.Seal = %v, want ErrNilSealer", err)
	}
	for i, b := range data {
		if b != 0 {
			t.Fatalf("data[%d] = %#x after a refused Seal; the ownership contract wipes on every path", i, b)
		}
	}
}

// TestSealer_ModeString covers the diagnostic surface, including a value that
// names no mode, which prints its number rather than garbage.
func TestSealer_ModeString(t *testing.T) {
	for want, m := range map[string]Mode{
		"ModeRootKey":      ModeRootKey,
		"ModePerOperation": ModePerOperation,
		"Mode(99)":         Mode(99),
	} {
		if got := m.String(); got != want {
			t.Errorf("Mode(%d).String() = %q, want %q", uint8(m), got, want)
		}
	}
}

// TestSealer_SweptTranslation pins hierarchyFailure as a pure function, since
// the race it serves (a WipeAll between an operation's liveness check and its
// borrow) cannot be held open deterministically. A dead hierarchy key reports
// ErrSealerWiped; a destroyed per-call enclave with the hierarchy intact stays
// ErrEnclaveDestroyed; every other error passes through.
func TestSealer_SweptTranslation(t *testing.T) {
	other := errors.New("unrelated failure")

	if got := swept(ErrEnclaveDestroyed); !errors.Is(got, ErrSealerWiped) {
		t.Errorf("swept(ErrEnclaveDestroyed) = %v, want ErrSealerWiped", got)
	}
	if got := swept(other); !errors.Is(got, other) || errors.Is(got, ErrSealerWiped) {
		t.Errorf("swept(unrelated) = %v, want it untouched", got)
	}

	alive, err := newMemorySized(kekBytes)
	if err != nil {
		t.Fatalf("allocating a live key: %v", err)
	}
	defer func() { _ = alive.Destroy() }()
	dead, err := newMemorySized(kekBytes)
	if err != nil {
		t.Fatalf("allocating a key to kill: %v", err)
	}
	if err := dead.Destroy(); err != nil {
		t.Fatalf("destroying it: %v", err)
	}

	if got := hierarchyFailure(ErrEnclaveDestroyed, alive, dead); !errors.Is(got, ErrSealerWiped) {
		t.Errorf("hierarchyFailure with a dead hierarchy key = %v, want ErrSealerWiped", got)
	}
	got := hierarchyFailure(ErrEnclaveDestroyed, alive)
	if errors.Is(got, ErrSealerWiped) || !errors.Is(got, ErrEnclaveDestroyed) {
		t.Errorf("hierarchyFailure with the hierarchy intact = %v, want ErrEnclaveDestroyed and NOT ErrSealerWiped: "+
			"a per-call enclave lost to a sweep is not a wiped sealer", got)
	}
	if got := hierarchyFailure(other, dead); !errors.Is(got, other) || errors.Is(got, ErrSealerWiped) {
		t.Errorf("hierarchyFailure(unrelated) = %v, want it untouched", got)
	}
	if got := hierarchyFailure(ErrSealedAuthentication, dead); !errors.Is(got, ErrSealedAuthentication) {
		t.Errorf("hierarchyFailure must not rewrite authentication failures; got %v", got)
	}
}

// TestSealer_NilProvidersAreRefusedAtConstruction pins that a typed nil (a
// non-nil interface value that would panic at the first Seal) and an untyped
// nil are both refused rather than defaulted to the software provider.
func TestSealer_NilProvidersAreRefusedAtConstruction(t *testing.T) {
	providers := map[string]any{
		"untyped nil":            nil,
		"typed-nil software":     (*softwareProvider)(nil),
		"typed-nil KeyProtector": (*mapKeyProtector)(nil),
		"typed-nil RootUnsealer": (*fixedRootUnsealer)(nil),
	}
	for _, m := range []Mode{ModeRootKey, ModePerOperation} {
		for name, p := range providers {
			t.Run(m.String()+"/"+name, func(t *testing.T) {
				s, err := NewSealer(providerOption(p, m))
				if !errors.Is(err, ErrInvalidProvider) {
					t.Errorf("NewSealer(%s, %v) = %v, want ErrInvalidProvider", name, m, err)
				}
				if s != nil {
					t.Errorf("NewSealer(%s, %v) returned a sealer alongside its refusal", name, m)
				}
			})
		}
	}

	// Control: the refusal is about nil, not about the option — the same
	// call with live providers still constructs (the mismatch test covers
	// the wrong-interface cases).
	if _, err := newEnvelopeSealer(WithRootUnsealer(newSoftwareProvider())); err != nil {
		t.Errorf("NewSealer(live provider): %v", err)
	}
}

// TestSealer_WithKEKRotationLimitIsValidated pins the option's bounds: zero,
// one above 2^31, or any value for ModePerOperation is refused at
// construction; the bounds themselves are accepted.
func TestSealer_WithKEKRotationLimitIsValidated(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []SealerOption
		ok   bool
	}{
		{"zero", []SealerOption{WithKEKRotationLimit(0)}, false},
		{"above the safe bound", []SealerOption{WithKEKRotationLimit(kekMessageLimit + 1)}, false},
		{"per-operation mode has no KEK", []SealerOption{WithKeyProtector(newSoftwareProvider()), WithKEKRotationLimit(10)}, false},
		{"one", []SealerOption{WithKEKRotationLimit(1)}, true},
		{"the safe bound", []SealerOption{WithKEKRotationLimit(kekMessageLimit)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := newEnvelopeSealer(tc.opts...)
			if tc.ok {
				if err != nil {
					t.Fatalf("NewSealer = %v, want success", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidRotationLimit) || s != nil {
				t.Fatalf("NewSealer = (%v, %v), want (nil, ErrInvalidRotationLimit)", s, err)
			}
		})
	}
}

// TestSealed_OpenReturnsAFrozenEnclave pins that Open returns a
// read-only enclave, and that a refused freeze fails the open closed with no
// enclave and no reservation kept. It uses its own sealer, independent of the
// process sealer's state.
func TestSealed_OpenReturnsAFrozenEnclave(t *testing.T) {
	ctx := t.Context()
	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.sealData(ctx, []byte("final plaintext"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	e, err := v.openIn(ctx, newMemorySized)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	e.mu.RLock()
	mutable := e.m.mutable
	e.mu.RUnlock()
	if mutable {
		t.Error("Open returned a writable enclave; final plaintext must be frozen")
	}
	if err := e.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}

	a, err := newBudgetAllocator(16 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	prev := protectMemory
	swapSeam(t, &protectMemory, func(b []byte, p protection) error {
		if p == protReadOnly {
			return errors.New("mprotect denied by policy")
		}
		return prev(b, p)
	})
	got, err := openInAllocator(ctx, v, a)
	protectMemory = prev
	if err == nil {
		_ = got.Destroy()
		t.Fatal("OpenIn succeeded although its freeze was refused: writable plaintext was returned")
	}
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Errorf("OpenIn with the freeze refused = %v, want ErrLockedMemoryUnavailable", err)
	}
	if got != nil {
		t.Error("OpenIn returned an enclave alongside its error")
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after the open failed closed, want 0: the reservation was kept", used)
	}
}

// TestSealed_OpenInKeepsTheChargeWhenARefusedFreezeCannotRelease
// pins that when both the freeze and the destination's release are refused,
// the open fails closed and OpenIn's reservation stays charged until the
// WipeAll ledger reclaims the pages.
func TestSealed_OpenInKeepsTheChargeWhenARefusedFreezeCannotRelease(t *testing.T) {
	ctx := t.Context()
	s, err := newEnvelopeSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.sealData(ctx, []byte("final plaintext"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()
	a, err := newBudgetAllocator(16 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	prevProtect, prevUnmap := protectMemory, unmapMemory
	// The stranded destination is on the orphan ledger, so it is reclaimed the
	// way production reclaims it — by a sweep once the refusal lifts.
	// Registered first, the sweep runs after the seams are restored.
	t.Cleanup(func() { _, _ = WipeAll(context.Background()) })
	swapSeam(t, &protectMemory, func(b []byte, p protection) error {
		if p == protReadOnly {
			return errors.New("mprotect denied by policy")
		}
		return prevProtect(b, p)
	})
	swapSeam(t, &unmapMemory, func([]byte) error { return errors.New("munmap: cannot allocate memory") })

	got, err := openInAllocator(ctx, v, a)
	protectMemory, unmapMemory = prevProtect, prevUnmap
	if err == nil {
		_ = got.Destroy()
		t.Fatal("OpenIn succeeded although its freeze was refused")
	}
	if got != nil {
		t.Error("OpenIn returned an enclave alongside its error")
	}
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Errorf("OpenIn = %v, want ErrLockedMemoryUnavailable", err)
	}
	if used := a.InUse(); used == 0 {
		t.Fatal("InUse = 0 although the destination's pages were never released: the charge was refunded early")
	}

	// Once the refusal lifts, the ledger reclaims the pages and the charge
	// goes back with them.
	if _, err := WipeAll(ctx); err != nil {
		t.Fatalf("WipeAll: %v", err)
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after the sweep reclaimed the destination, want 0", used)
	}
}

// The tests below pin context handling: every provider-reaching path honors
// the caller's context, and no Sealer or Sealed lock is held across a
// provider call. Nothing sleeps or races a clock: providers block on channels
// the test closes, and deadlines are manualContexts the test expires.

// requireSealCanceled asserts the seal-side shape of an abandoned call.
func requireSealCanceled(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, ErrSealFailed) || !errors.Is(err, want) {
		t.Fatalf("Seal = %v, want an error matching BOTH ErrSealFailed and %v", err, want)
	}
	if errors.Is(err, ErrSealedAuthentication) || errors.Is(err, ErrSealerWiped) {
		t.Fatalf("Seal = %v: an abandoned call must not read as a forgery or a sweep", err)
	}
}

// requireOpenCanceled asserts the open-side shape of an abandoned call.
func requireOpenCanceled(t *testing.T, e ByteAccess, err, want error) {
	t.Helper()
	if e != nil {
		e.Destroy()
		t.Fatal("Open returned a destination alongside its error")
	}
	if !errors.Is(err, ErrOpenFailed) || !errors.Is(err, want) {
		t.Fatalf("Open = %v, want an error matching BOTH ErrOpenFailed and %v", err, want)
	}
	if errors.Is(err, ErrSealedAuthentication) {
		t.Fatalf("Open = %v: a caller that gave up was reported as a forgery", err)
	}
}

// TestSealer_EndedContextIsRefusedBeforeAnyWork pins the entry half of the
// contract, for both modes and both ways a context ends: the call fails with
// the operation's sentinel AND the context's error, the provider is never
// reached, the ownership contract still wipes the caller's material, and the
// sealed value an abandoned Open was aimed at is intact.
func TestSealer_EndedContextIsRefusedBeforeAnyWork(t *testing.T) {
	for _, m := range []Mode{ModeRootKey, ModePerOperation} {
		for name, ec := range endedContexts(t) {
			t.Run(m.String()+"/"+name, func(t *testing.T) {
				p := newBlockingProvider()
				s, err := newEnvelopeSealer(providerOption(p, m))
				if err != nil {
					t.Fatalf("NewSealer: %v", err)
				}

				data := append([]byte(nil), sealedMaterial...)
				_, err = s.sealData(ec.ctx, data)
				requireSealCanceled(t, err, ec.want)
				if !bytes.Equal(data, make([]byte, len(data))) {
					t.Error("a refused Seal left the caller's material in place; the ownership contract wipes on every path")
				}
				if got := p.callCount(); got != 0 {
					t.Errorf("the provider was called %d times by a Seal whose context had already ended", got)
				}

				v, err := s.sealData(t.Context(), append([]byte(nil), sealedMaterial...))
				if err != nil {
					t.Fatalf("control Seal with a live context: %v", err)
				}
				defer v.Destroy()
				before := p.callCount()

				e, err := v.Open(ec.ctx)
				requireOpenCanceled(t, e, err, ec.want)

				a, err := newBudgetAllocator(16 * LockedSize(1))
				if err != nil {
					t.Fatalf("NewAllocator: %v", err)
				}
				e, err = byteAccess(openInAllocator(ec.ctx, v, a))
				requireOpenCanceled(t, e, err, ec.want)
				if a.InUse() != 0 {
					t.Errorf("an abandoned OpenIn charged %d bytes to the budget; it must cost nothing", a.InUse())
				}
				if got := p.callCount(); got != before {
					t.Errorf("the provider was called by an Open whose context had already ended")
				}

				// The value is intact: an abandoned open is retryable.
				e, err = v.Open(t.Context())
				if err != nil {
					t.Fatalf("Open with a live context after the refusals: %v", err)
				}
				defer e.Destroy()
				if !holds(e, sealedMaterial) {
					t.Error("the value opened to the wrong material after an abandoned open")
				}
			})
		}
	}
}

// TestSealer_CancellationReachesTheProvider pins propagation: the context a
// provider receives is the caller's, so canceling the caller's context
// releases a provider that honors it — on each of the three provider
// operations — and the call fails as canceled.
func TestSealer_CancellationReachesTheProvider(t *testing.T) {
	type op struct {
		mode Mode
		// prepare returns the call to cancel; it runs with the provider not
		// yet blocking, so a value can be sealed first.
		prepare func(t *testing.T, s *envelopeSealer) func(ctx context.Context) error
		isOpen  bool
	}
	seal := func(t *testing.T, s *envelopeSealer) func(ctx context.Context) error {
		return func(ctx context.Context) error {
			_, err := s.sealData(ctx, append([]byte(nil), sealedMaterial...))
			return err
		}
	}
	open := func(t *testing.T, s *envelopeSealer) func(ctx context.Context) error {
		v, err := s.sealData(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		t.Cleanup(func() { _ = v.Destroy() })
		return func(ctx context.Context) error {
			e, err := v.Open(ctx)
			if e != nil {
				e.Destroy()
			}
			return err
		}
	}
	ops := map[string]op{
		"UnsealRoot via Seal": {mode: ModeRootKey, prepare: seal},
		"Protect via Seal":    {mode: ModePerOperation, prepare: seal},
		"Unprotect via Open":  {mode: ModePerOperation, prepare: open, isOpen: true},
	}

	for name, tc := range ops {
		t.Run(name, func(t *testing.T) {
			p := newBlockingProvider()
			p.honor = true
			s, err := newEnvelopeSealer(providerOption(p, tc.mode))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			call := tc.prepare(t, s)

			// Block from here on; drain what preparation produced.
			p.mu.Lock()
			p.release = make(chan struct{})
			p.mu.Unlock()
			for len(p.entered) > 0 {
				<-p.entered
			}

			ctx, cancel := context.WithCancelCause(t.Context())
			why := errors.New("the request this seal served was abandoned")
			result := make(chan error, 1)
			go func() { result <- call(ctx) }()

			<-p.entered // inside the provider, blocked on the caller's context
			cancel(why)
			err = <-result

			sentinel := ErrSealFailed
			if tc.isOpen {
				sentinel = ErrOpenFailed
			}
			if !errors.Is(err, sentinel) || !errors.Is(err, context.Canceled) {
				t.Fatalf("%s = %v, want an error matching %v and context.Canceled", name, err, sentinel)
			}
			if !errors.Is(err, why) {
				t.Errorf("%s = %v, want the canceler's context.Cause reachable too", name, err)
			}
			if errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("%s = %v: cancellation reported as a forgery", name, err)
			}

			p.mu.Lock()
			got := p.gotCtx[len(p.gotCtx)-1]
			p.mu.Unlock()
			if got.Err() == nil {
				t.Error("the context the provider received did not end when the caller's did; it is not the caller's context")
			}
		})
	}
}

// TestSealer_ContextEndingDuringASuccessfulCallIsHonoured pins the AFTER half:
// a provider that completes its work while the caller's context ends must not
// turn into a success the caller stopped waiting for — and, for the root
// unseal, must not cost the root: the unseal succeeded, so it is published
// and never asked for again.
func TestSealer_ContextEndingDuringASuccessfulCallIsHonoured(t *testing.T) {
	t.Run("Protect", func(t *testing.T) {
		p := newBlockingProvider()
		s, err := newEnvelopeSealer(WithKeyProtector(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		p.beforeReturn = cancel
		_, err = s.sealData(ctx, append([]byte(nil), sealedMaterial...))
		requireSealCanceled(t, err, context.Canceled)
	})

	t.Run("Unprotect", func(t *testing.T) {
		p := newBlockingProvider()
		s, err := newEnvelopeSealer(WithKeyProtector(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.sealData(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		ctx, cancel := context.WithCancel(t.Context())
		p.beforeReturn = cancel
		e, err := v.Open(ctx)
		requireOpenCanceled(t, e, err, context.Canceled)
	})

	t.Run("UnsealRoot", func(t *testing.T) {
		p := newBlockingProvider()
		s, err := newEnvelopeSealer(WithRootUnsealer(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		p.beforeReturn = cancel
		_, err = s.sealData(ctx, append([]byte(nil), sealedMaterial...))
		requireSealCanceled(t, err, context.Canceled)
		p.beforeReturn = nil

		if published, herr := hierarchyState(s); !published || herr != nil {
			t.Fatalf("hierarchy state = (%t, %v) after a successful unseal whose caller gave up; "+
				"the root it delivered was discarded", published, herr)
		}
		v, err := s.sealData(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("the next Seal: %v", err)
		}
		v.Destroy()
		if got := p.callCount(); got != 1 {
			t.Errorf("UnsealRoot was called %d times, want 1: a successful unseal was repeated because "+
				"the caller that triggered it had gone", got)
		}
	})
}

// TestSealed_DestroyDoesNotWaitForABlockedOpen pins the Sealed
// half of "no lock across a provider": Destroy has no context, so it must not
// wait for an Open stuck in Unprotect. The in-flight open completes against
// the envelope it pinned, the ciphertext is wiped by the last open out, and
// opens after the Destroy are refused.
func TestSealed_DestroyDoesNotWaitForABlockedOpen(t *testing.T) {
	p := newBlockingProvider()
	s, err := newEnvelopeSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.sealData(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	<-p.entered // the Protect
	sealed, blob := v.sealed, v.blob

	p.mu.Lock()
	p.release = make(chan struct{})
	p.mu.Unlock()

	opened := make(chan ByteAccess, 1)
	openErr := make(chan error, 1)
	go func() {
		e, err := v.Open(t.Context())
		opened <- e
		openErr <- err
	}()
	<-p.entered // the open is inside Unprotect

	v.Destroy() // must return while the open is still blocked
	if v.IsAlive() {
		t.Error("IsAlive after Destroy")
	}
	if _, err := v.Open(t.Context()); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open after Destroy = %v, want ErrEnclaveDestroyed", err)
	}
	if bytes.Equal(sealed, make([]byte, len(sealed))) {
		t.Fatal("Destroy wiped the ciphertext under an open still reading it")
	}

	close(p.release)
	e := <-opened
	if err := <-openErr; err != nil {
		t.Fatalf("the open in flight across Destroy: %v", err)
	}
	defer e.Destroy()
	if !holds(e, sealedMaterial) {
		t.Error("the open in flight across Destroy recovered the wrong material")
	}
	if !bytes.Equal(sealed, make([]byte, len(sealed))) || !bytes.Equal(blob, make([]byte, len(blob))) {
		t.Error("the last open out did not wipe the envelope Destroy left to it")
	}
}

// TestNewSealed_EndedContextInstallsNothing pins that NewSealed with an ended
// context does not lazily install the software default, which would make the
// deployment's own SetSealer fail with ErrSealerInstalled.
func TestNewSealed_EndedContextInstallsNothing(t *testing.T) {
	for name, ec := range endedContexts(t) {
		t.Run(name, func(t *testing.T) {
			freshProcessSealer(t)

			data := append([]byte(nil), sealedMaterial...)
			_, err := newSealed(ec.ctx, data)
			requireSealCanceled(t, err, ec.want)
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Error("a refused NewSealed left the caller's material in place")
			}

			own, err := newEnvelopeSealer(WithKeyProtector(newMapKeyProtector(t)))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			if err := SetSealer(own); err != nil {
				t.Fatalf("SetSealer after a refused NewSealed = %v: the refusal installed the default", err)
			}
		})
	}
}

// TestSealer_AuthenticationVerdictSurvivesCancellation pins the documented
// precedence: an authentication failure the PROVIDER reported is a security
// signal and stays visible even when the caller's context ended before the
// post-call check — the error matches ErrSealedAuthentication AND the
// cancellation. Only a refusal the provider attributed to the context alone is
// kept clear of ErrSealedAuthentication.
func TestSealer_AuthenticationVerdictSurvivesCancellation(t *testing.T) {
	p := &errorThenCancelProtector{inner: newSoftwareProvider(), openErr: ErrSealedAuthentication}
	s, err := newEnvelopeSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.sealData(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	ctx, cancel := context.WithCancel(t.Context())
	p.cancel = cancel
	e, err := v.Open(ctx)
	if e != nil {
		e.Destroy()
		t.Fatal("Open returned a destination alongside its error")
	}
	for _, want := range []error{ErrSealedAuthentication, ErrOpenFailed, context.Canceled} {
		if !errors.Is(err, want) {
			t.Errorf("Open = %v, does not match %v", err, want)
		}
	}
}

// TestSealed_OnlyTheLastOpenOutWipes parks two opens, runs Destroy,
// and releases them one at a time (the first succeeding, the second
// canceled): the envelope must survive the first exit and be wiped by the
// second.
func TestSealed_OnlyTheLastOpenOutWipes(t *testing.T) {
	p := &parkingProtector{inner: newSoftwareProvider(), arrivals: make(chan chan error)}
	s, err := newEnvelopeSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.sealData(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	sealed, blob := v.sealed, v.blob
	zero := func(b []byte) bool { return bytes.Equal(b, make([]byte, len(b))) }

	type result struct {
		e   ByteAccess
		err error
	}
	firstOut, secondOut := make(chan result, 1), make(chan result, 1)
	secondCtx, cancelSecond := context.WithCancel(t.Context())
	defer cancelSecond()

	go func() { e, err := v.Open(t.Context()); firstOut <- result{e, err} }()
	firstGate := <-p.arrivals
	go func() { e, err := v.Open(secondCtx); secondOut <- result{e, err} }()
	secondGate := <-p.arrivals

	v.Destroy()

	firstGate <- nil
	r := <-firstOut
	if r.err != nil {
		t.Fatalf("the first open in flight across Destroy: %v", r.err)
	}
	if !holds(r.e, sealedMaterial) {
		t.Error("the first open recovered the wrong material")
	}
	r.e.Destroy()
	if zero(sealed) || zero(blob) {
		t.Fatal("the first open out wiped the envelope while the second was still reading it")
	}

	cancelSecond()
	secondGate <- secondCtx.Err()
	r = <-secondOut
	requireOpenCanceled(t, r.e, r.err, context.Canceled)
	if !zero(sealed) || !zero(blob) {
		t.Error("the last open out — leaving through a cancellation — did not wipe the envelope")
	}
}

// TestSealer_PassThroughSentinelsAreJoinedWhenTheContextEnds pins that a
// pass-through sentinel the provider returns (ErrSealerWiped,
// ErrLockedMemoryUnavailable, ErrProviderMessageLimit) is joined with the
// cancellation when the caller's context has ended by the time the provider
// returns: it matches the operation's sentinel, the context's error and the
// provider's sentinel.
func TestSealer_PassThroughSentinelsAreJoinedWhenTheContextEnds(t *testing.T) {
	for _, sentinel := range []error{ErrSealerWiped, ErrLockedMemoryUnavailable} {
		t.Run("open/"+sentinel.Error(), func(t *testing.T) {
			p := &errorThenCancelProtector{inner: newSoftwareProvider()}
			s, err := newEnvelopeSealer(WithKeyProtector(p))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			v, err := s.sealData(t.Context(), append([]byte(nil), sealedMaterial...))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			defer v.Destroy()

			ctx, cancel := context.WithCancel(t.Context())
			p.cancel, p.openErr = cancel, sentinel
			e, err := v.Open(ctx)
			if e != nil {
				e.Destroy()
				t.Fatal("Open returned a destination alongside its error")
			}
			for _, want := range []error{sentinel, ErrOpenFailed, context.Canceled} {
				if !errors.Is(err, want) {
					t.Errorf("Open = %v, does not match %v", err, want)
				}
			}
			if errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("Open = %v reads as a forgery", err)
			}

			// Control: with a live context the same sentinel passes through
			// untouched — not joined under ErrOpenFailed.
			p.cancel = func() {}
			if _, err := v.Open(t.Context()); err != sentinel {
				t.Errorf("Open with a live context = %v, want %v untouched", err, sentinel)
			}
		})
	}

	for _, sentinel := range []error{ErrSealerWiped, ErrLockedMemoryUnavailable, ErrProviderMessageLimit} {
		t.Run("seal/"+sentinel.Error(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			p := &errorThenCancelProtector{inner: newSoftwareProvider(), cancel: cancel, protectErr: sentinel}
			s, err := newEnvelopeSealer(WithKeyProtector(p))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			_, err = s.sealData(ctx, append([]byte(nil), sealedMaterial...))
			for _, want := range []error{sentinel, ErrSealFailed, context.Canceled} {
				if !errors.Is(err, want) {
					t.Errorf("Seal = %v, does not match %v", err, want)
				}
			}

			p.cancel = func() {}
			if _, err := s.sealData(t.Context(), append([]byte(nil), sealedMaterial...)); err != sentinel {
				t.Errorf("Seal with a live context = %v, want %v untouched", err, sentinel)
			}
		})
	}
}

func TestSealer_DestroyReleasesEverythingAndFailsClosed(t *testing.T) {
	cases := map[string][]SealerOption{
		"root key, default provider":    nil,
		"root key, rotated generations": {WithKEKRotationLimit(1)},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			base := ledgerCount()

			s, err := newEnvelopeSealer(opts...)
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			var values []*sealedValue
			for i := range 3 {
				v, err := s.sealData(ctx, fmt.Appendf(nil, "secret-%d", i))
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				values = append(values, v)
			}
			if ledgerCount() == base {
				t.Fatal("sealing registered no keys; the test would prove nothing")
			}

			if err := s.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			if got := ledgerCount(); got != base {
				t.Errorf("ledger holds %d entries after Destroy, want %d: the sealer's keys were not released", got, base)
			}
			if s.owned == nil || s.owned.Health() == nil {
				t.Error("the default provider the sealer created was not destroyed with it")
			}
			if s.kekBlobs != nil {
				t.Error("retired KEK blobs are still retained after Destroy")
			}

			data := []byte("after-destroy")
			if _, err := s.sealData(ctx, data); !errors.Is(err, ErrSealerDestroyed) {
				t.Errorf("Seal after Destroy = %v, want ErrSealerDestroyed", err)
			}
			if !bytes.Equal(data, make([]byte, len(data))) {
				t.Error("Seal after Destroy did not wipe the caller's material")
			}
			for _, v := range values {
				if e, err := v.Open(ctx); !errors.Is(err, ErrSealerDestroyed) {
					_ = e.Destroy()
					t.Errorf("Open after Destroy = %v, want ErrSealerDestroyed", err)
				}
				if err := v.Openable(); !errors.Is(err, ErrSealerDestroyed) {
					t.Errorf("Openable after Destroy = %v, want ErrSealerDestroyed", err)
				}
				v.Destroy()
			}
			if err := s.Destroy(); err != nil {
				t.Errorf("second Destroy = %v, want nil", err)
			}
		})
	}

	var nilSealer *envelopeSealer
	if err := nilSealer.Destroy(); err != nil {
		t.Errorf("nil Sealer Destroy = %v, want nil", err)
	}
}

func TestSealer_DestroyNeverDestroysAnInjectedProvider(t *testing.T) {
	ctx := t.Context()
	for _, mode := range []Mode{ModeRootKey, ModePerOperation} {
		t.Run(mode.String(), func(t *testing.T) {
			p := newSoftwareProvider()
			t.Cleanup(func() { _ = p.Destroy() })
			s, err := newEnvelopeSealer(providerOption(p, mode))
			if err != nil {
				t.Fatalf("NewSealer: %v", err)
			}
			v, err := s.sealData(ctx, []byte("x"))
			if err != nil {
				t.Fatalf("Seal: %v", err)
			}
			v.Destroy()
			if err := s.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			blob, err := p.Protect(ctx, make([]byte, RootKeyBytes))
			if err != nil {
				t.Fatalf("the injected provider stopped working after the sealer's Destroy: %v", err)
			}
			if len(blob) == 0 {
				t.Fatal("empty blob")
			}
		})
	}
}

// TestSealer_DestroyReleasesAPendingRootLeftByAFailedMint covers the pending
// state with no initialization in flight: a successful unseal whose KEK mint
// failed retains the root, and Destroy must take it.
func TestSealer_DestroyReleasesAPendingRootLeftByAFailedMint(t *testing.T) {
	ctx := t.Context()
	base := ledgerCount()
	s, err := newEnvelopeSealer(WithRootUnsealer(&fixedRootUnsealer{fill: 0x11}))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	// Seal locks the DEK, then the root destination, then the KEK.
	failNthLock(t, 3)
	if _, err := s.sealData(ctx, []byte("x")); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("Seal with the KEK mint refused = %v, want ErrLockedMemoryUnavailable", err)
	}
	if s.pendingRoot == nil {
		t.Fatal("no pending root after a failed mint; the test would prove nothing")
	}
	if err := s.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if got := ledgerCount(); got != base {
		t.Errorf("ledger holds %d entries, want %d: the pending root outlived Destroy", got, base)
	}
}

func TestSealer_DestroyRacesSealsAndOpens(t *testing.T) {
	ctx := t.Context()
	base := ledgerCount()
	s, err := newEnvelopeSealer(WithKEKRotationLimit(3))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.sealData(ctx, []byte("shared"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Go(func() {
			<-start
			for range 20 {
				if w, err := s.sealData(ctx, []byte("x")); err == nil {
					w.Destroy()
				} else if !errors.Is(err, ErrSealerDestroyed) {
					t.Errorf("Seal: %v", err)
				}
				if e, err := v.Open(ctx); err == nil {
					_ = e.Destroy()
				} else if !errors.Is(err, ErrSealerDestroyed) {
					t.Errorf("Open: %v", err)
				}
			}
		})
	}
	close(start)
	if err := s.Destroy(); err != nil {
		t.Errorf("Destroy: %v", err)
	}
	wg.Wait()
	if got := ledgerCount(); got != base {
		t.Errorf("ledger holds %d entries, want %d", got, base)
	}
}

// TestSealer_DestroyDuringAProviderCallFailsTheCall pins that a seal or open
// whose provider call straddles Destroy does not succeed after Destroy
// returned: Destroy waits for no provider, so the call rechecks.
func TestSealer_DestroyDuringAProviderCallFailsTheCall(t *testing.T) {
	ctx := t.Context()
	newSealer := func(t *testing.T) (*envelopeSealer, *blockingProvider) {
		t.Helper()
		p := newBlockingProvider()
		t.Cleanup(func() { _ = p.inner.Destroy() })
		s, err := newEnvelopeSealer(WithKeyProtector(p))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		return s, p
	}

	t.Run("seal", func(t *testing.T) {
		s, p := newSealer(t)
		p.beforeReturn = func() {
			if err := s.Destroy(); err != nil {
				t.Errorf("Destroy: %v", err)
			}
		}
		v, err := s.sealData(ctx, []byte("x"))
		if !errors.Is(err, ErrSealerDestroyed) {
			v.Destroy()
			t.Fatalf("Seal straddling Destroy = %v, want ErrSealerDestroyed", err)
		}
	})

	t.Run("open", func(t *testing.T) {
		base := ledgerCount()
		s, p := newSealer(t)
		v, err := s.sealData(ctx, []byte("x"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()
		p.beforeReturn = func() {
			if err := s.Destroy(); err != nil {
				t.Errorf("Destroy: %v", err)
			}
		}
		e, err := v.Open(ctx)
		if !errors.Is(err, ErrSealerDestroyed) {
			_ = e.Destroy()
			t.Fatalf("Open straddling Destroy = %v, want ErrSealerDestroyed", err)
		}
		_ = p.inner.Destroy()
		if got := ledgerCount(); got != base {
			t.Errorf("ledger holds %d entries, want %d", got, base)
		}
	})
}

func TestSealer_ProviderBlobIsCopied(t *testing.T) {
	ctx := t.Context()
	p := &reusingProtector{inner: newSoftwareProvider(), buf: make([]byte, 0, 256)}
	t.Cleanup(func() { _ = p.inner.Destroy() })
	s, err := newEnvelopeSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	a, err := s.sealData(ctx, []byte("first"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	b, err := s.sealData(ctx, []byte("second"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer b.Destroy()

	e, err := a.Open(ctx)
	if err != nil {
		t.Fatalf("opening the first value after the provider reused its blob buffer: %v", err)
	}
	_ = e.Destroy()

	// Destroying a value wipes the sealer's copy, never the provider's slice.
	held := bytes.Clone(p.buf)
	a.Destroy()
	if !bytes.Equal(p.buf, held) {
		t.Fatal("Sealed.Destroy wiped the provider's own blob slice")
	}
	e, err = b.Open(ctx)
	if err != nil {
		t.Fatalf("opening the second value: %v", err)
	}
	_ = e.Destroy()
}

func TestSealer_ZeroValueFailsWithoutPanicking(t *testing.T) {
	ctx := t.Context()
	var s envelopeSealer
	data := []byte("material")
	if _, err := s.sealData(ctx, data); !errors.Is(err, ErrSealerNotConstructed) {
		t.Errorf("zero-value Seal = %v, want ErrSealerNotConstructed", err)
	}
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Error("zero-value Seal did not wipe the caller's material")
	}
	if _, err := s.open(ctx, sealedVersionCurrent, []byte("blob"), []byte("sealed"), 4, newMemorySized, true); !errors.Is(err, ErrSealerNotConstructed) {
		t.Errorf("zero-value open = %v, want ErrSealerNotConstructed", err)
	}
	if err := s.Destroy(); err != nil {
		t.Errorf("zero-value Destroy = %v, want nil", err)
	}
}

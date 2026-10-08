// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package enclave_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Covers sealed.go: between opens the process holds only ciphertext, measured
// by sweeping process memory; and OpenWith's admission against a budget.

// TestSealing_SealedValueHoldsNoPlaintextBetweenOpens follows one secret through a
// sealed value's life, in both modes, sweeping every readable mapping at each
// step:
//
//   - in the caller's heap slice before sealing — the sweep's control for the
//     Go heap, where a leak would most plausibly land;
//   - NOWHERE once sealed: Seal wiped the slice and left no plaintext in any
//     buffer, stack or AEAD scratch it used;
//   - in exactly the enclave Open returns, and nowhere else, while it is open
//     — the control for locked mappings, and proof the plaintext was decrypted
//     straight into locked pages;
//   - nowhere again once that enclave is destroyed, and likewise for OpenWith;
//   - nowhere after a shutdown sweep reclaims an enclave still open at exit.
func TestSealing_SealedValueHoldsNoPlaintextBetweenOpens(t *testing.T) {
	for _, mode := range sealerModes {
		t.Run(mode.String(), func(t *testing.T) {
			isolated(t, childOpts{}, func(t *testing.T) {
				ctx := context.Background()
				s, err := enclave.NewSealer(providerOption(enclave.NewSoftwareProvider(), mode))
				if err != nil {
					t.Fatalf("NewSealer: %v", err)
				}
				n := newNeedle(t)
				buf := heapBytes(needleLen)
				n.fill(buf)
				hits, scanned := sweep(t, n)
				requireHitsExactly(t, "caller's heap slice, before sealing", hits, scanned, addrOfSlice(buf))

				v, err := s.Seal(ctx, buf)
				if err != nil {
					t.Fatalf("Seal: %v", err)
				}
				hits, scanned = sweep(t, n)
				requireHitsExactly(t, "sealed, at rest", hits, scanned)

				o, err := v.Open(ctx)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				hits, scanned = sweep(t, n)
				requireHitsExactly(t, "open", hits, scanned, dataAddr(t, o))
				if err := o.Destroy(); err != nil {
					t.Fatalf("Destroy: %v", err)
				}
				hits, scanned = sweep(t, n)
				requireHitsExactly(t, "after the opened enclave was destroyed", hits, scanned)

				a, err := enclave.NewAllocator(enclave.LockedSize(needleLen))
				if err != nil {
					t.Fatalf("NewAllocator: %v", err)
				}
				o, err = v.OpenWith(ctx, a)
				if err != nil {
					t.Fatalf("OpenWith: %v", err)
				}
				hits, scanned = sweep(t, n)
				requireHitsExactly(t, "open through OpenWith", hits, scanned, dataAddr(t, o))
				if err := o.Destroy(); err != nil {
					t.Fatalf("Destroy: %v", err)
				}
				hits, scanned = sweep(t, n)
				requireHitsExactly(t, "after the OpenWith enclave was destroyed", hits, scanned)

				// Open at exit: the shutdown sweep reclaims it.
				o, err = v.Open(ctx)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				hits, scanned = sweep(t, n)
				requireHitsExactly(t, "open at exit", hits, scanned, dataAddr(t, o))
				if n, err := enclave.WipeAll(ctx); n != 0 || err != nil {
					t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
				}
				if o.IsAlive() {
					t.Fatalf("the enclave open at exit survived WipeAll")
				}
				hits, scanned = sweep(t, n)
				requireHitsExactly(t, "after WipeAll", hits, scanned)
			})
		})
	}
}

// TestLockedMemoryBudget_OpenWithAdmitsAgainstTheBudget: OpenWith charges the plaintext page to
// the caller's allocator, refuses by budget before any decryption once that is
// spent (the value surviving intact), returns the charge on Destroy, and
// refuses a nil allocator rather than falling back to an unbudgeted open.
func TestLockedMemoryBudget_OpenWithAdmitsAgainstTheBudget(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		page := enclave.LockedSize(1)
		s, err := enclave.NewSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		n := newNeedle(t)
		v := sealNeedle(t, ctx, s, n)

		if _, err := v.OpenWith(ctx, nil); !errors.Is(err, enclave.ErrNilAllocator) {
			t.Fatalf("OpenWith(nil): %v, want ErrNilAllocator", err)
		}
		a, err := enclave.NewAllocator(page)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		o, err := v.OpenWith(ctx, a)
		if err != nil {
			t.Fatalf("OpenWith: %v", err)
		}
		if a.InUse() != page {
			t.Fatalf("InUse after OpenWith = %d, want %d", a.InUse(), page)
		}
		_, err = v.OpenWith(ctx, a)
		requireBudgetError(t, "OpenWith past the budget", err, page, page, page)
		if err := o.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if a.InUse() != 0 {
			t.Fatalf("InUse after Destroy = %d, want 0", a.InUse())
		}
		requireOpensTo(t, ctx, v, n) // the refusal left the value intact
		o, err = v.OpenWith(ctx, a)
		if err != nil {
			t.Fatalf("OpenWith once the budget was returned: %v", err)
		}
		var ok bool
		if err := o.WithBytes(func(b []byte) error { ok = n.equals(b); return nil }); err != nil || !ok {
			t.Fatalf("OpenWith opened to the wrong material: ok %t, err %v", ok, err)
		}
		if n, err := enclave.WipeAll(ctx); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
		if a.InUse() != 0 {
			t.Fatalf("InUse after WipeAll reclaimed the open enclave = %d, want 0", a.InUse())
		}
	})
}

// TestSealing_DestroyedAndNilSealedValuesAnswerSafely covers what every accessor of a
// destroyed — or nil — SealedEnclave reports: each answers with the
// documented sentinel, Destroy is idempotent, and String never prints the
// material.
func TestSealing_DestroyedAndNilSealedValuesAnswerSafely(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()

		var nilSealed *enclave.SealedEnclave
		if nilSealed.IsAlive() {
			t.Error("a nil *SealedEnclave reports itself alive")
		}
		if err := nilSealed.Openable(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Openable of a nil *SealedEnclave = %v, want ErrEnclaveDestroyed", err)
		}
		nilSealed.Destroy()
		a, err := enclave.NewAllocator(enclave.LockedSize(1))
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		if _, err := nilSealed.Open(ctx); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Open of a nil *SealedEnclave = %v, want ErrEnclaveDestroyed", err)
		}
		if _, err := nilSealed.OpenWith(ctx, a); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("OpenWith of a nil *SealedEnclave = %v, want ErrEnclaveDestroyed", err)
		}

		v, err := enclave.NewSealed(ctx, []byte("a value to destroy"))
		if err != nil {
			t.Fatalf("NewSealed: %v", err)
		}
		if s := v.String(); s == "" || strings.Contains(s, "a value to destroy") {
			t.Errorf("SealedEnclave.String() = %q: empty, or it prints the material", s)
		}
		v.Destroy()
		v.Destroy() // idempotent
		if v.IsAlive() {
			t.Error("a destroyed sealed value reports itself alive")
		}
		if err := v.Openable(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Openable after Destroy = %v, want ErrEnclaveDestroyed", err)
		}
		if _, err := v.Open(ctx); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Open after Destroy = %v, want ErrEnclaveDestroyed", err)
		}
		if _, err := v.OpenWith(ctx, a); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("OpenWith after Destroy = %v, want ErrEnclaveDestroyed", err)
		}
		if s := v.String(); !strings.Contains(strings.ToLower(s), "destroyed") {
			t.Errorf("SealedEnclave.String() after Destroy = %q, want it to say so", s)
		}
	})
}

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
	"fmt"
	"strings"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Covers sealed.go: between opens the process holds only ciphertext, measured
// by sweeping process memory; and OpenIn's admission against a budget.

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
//   - nowhere again once that enclave is destroyed, and likewise for OpenIn;
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
				o, err = openInAllocator(t, ctx, v, a)
				if err != nil {
					t.Fatalf("OpenIn: %v", err)
				}
				hits, scanned = sweep(t, n)
				requireHitsExactly(t, "open through OpenIn", hits, scanned, dataAddr(t, o))
				if err := o.Destroy(); err != nil {
					t.Fatalf("Destroy: %v", err)
				}
				hits, scanned = sweep(t, n)
				requireHitsExactly(t, "after the OpenIn enclave was destroyed", hits, scanned)

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

// TestLockedMemoryBudget_OpenInAdmitsAgainstTheBudget: OpenIn charges the plaintext page to
// the caller's allocator, refuses by budget before any decryption once that is
// spent (the value surviving intact), returns the charge on Destroy, and
// refuses a nil allocator rather than falling back to an unbudgeted open.
func TestLockedMemoryBudget_OpenInAdmitsAgainstTheBudget(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()
		page := enclave.LockedSize(1)
		s, err := enclave.NewSealer()
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		n := newNeedle(t)
		v := sealNeedle(t, ctx, s, n)

		if _, err := openInAllocator(t, ctx, v, nil); !errors.Is(err, enclave.ErrInvalidBackend) {
			t.Fatalf("OpenIn(nil): %v, want ErrInvalidBackend", err)
		}
		a, err := enclave.NewAllocator(page)
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}
		o, err := openInAllocator(t, ctx, v, a)
		if err != nil {
			t.Fatalf("OpenIn: %v", err)
		}
		if a.InUse() != page {
			t.Fatalf("InUse after OpenIn = %d, want %d", a.InUse(), page)
		}
		_, err = openInAllocator(t, ctx, v, a)
		requireBudgetError(t, "OpenIn past the budget", err, page, page, page)
		if err := o.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if a.InUse() != 0 {
			t.Fatalf("InUse after Destroy = %d, want 0", a.InUse())
		}
		requireOpensTo(t, ctx, v, n) // the refusal left the value intact
		o, err = openInAllocator(t, ctx, v, a)
		if err != nil {
			t.Fatalf("OpenIn once the budget was returned: %v", err)
		}
		var ok bool
		if err := o.WithBytes(func(b []byte) error { ok = n.equals(b); return nil }); err != nil || !ok {
			t.Fatalf("OpenIn opened to the wrong material: ok %t, err %v", ok, err)
		}
		if n, err := enclave.WipeAll(ctx); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
		if a.InUse() != 0 {
			t.Fatalf("InUse after WipeAll reclaimed the open enclave = %d, want 0", a.InUse())
		}
	})
}

// TestSealing_DestroyedSealedValuesAnswerSafely covers what every accessor of a
// destroyed Sealed reports: each answers with the documented sentinel,
// Destroy is idempotent, and String never prints the material. A nil Sealed
// cannot be built outside the package; the unit tests cover its receiver.
func TestSealing_DestroyedSealedValuesAnswerSafely(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		ctx := context.Background()

		v, err := enclave.NewSealed(ctx, []byte("a value to destroy"))
		if err != nil {
			t.Fatalf("NewSealed: %v", err)
		}
		if s := fmt.Sprint(v); s == "" || strings.Contains(s, "a value to destroy") {
			t.Errorf("Sealed.String() = %q: empty, or it prints the material", s)
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
		if _, err := v.OpenIn(ctx, enclave.DefaultBackend()); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("OpenIn after Destroy = %v, want ErrEnclaveDestroyed", err)
		}
		if s := fmt.Sprint(v); !strings.Contains(strings.ToLower(s), "destroyed") {
			t.Errorf("Sealed.String() after Destroy = %q, want it to say so", s)
		}
	})
}

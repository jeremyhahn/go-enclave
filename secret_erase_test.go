// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build goexperiment.runtimesecret && linux && !android && (amd64 || arm64)

package enclave

import (
	"crypto/cipher"
	"crypto/rand"
	"runtime"
	"testing"
	"unsafe"
)

// TestWithAEAD_ErasesTheKeyScheduleUnderRuntimeSecret is the proof behind
// KeyScheduleErasure (#98). An AES operation run through withAEAD — under
// runtime/secret.Do — must leave no copy of its key in process memory once
// the garbage collector has run, in either form crypto/aes stores it (byte
// exact on the hardware path, big-endian words on the generic one).
//
// The CONTROL comes first and is what makes the result mean anything: the
// very same operation run OUTSIDE secretDo, under a different key, leaves its
// key schedule findable after GC. A sweep that could not see that would pass
// the erasure check vacuously.
func TestWithAEAD_ErasesTheKeyScheduleUnderRuntimeSecret(t *testing.T) {
	if !KeyScheduleErasure() {
		t.Fatal("KeyScheduleErasure() = false in a build constrained to the erasing configuration")
	}

	// sealOnce performs one real AES-GCM seal under a fresh random key held in
	// locked memory, through run (withAEAD, or the unerased inner call), and
	// returns probe enclaves holding the key in both stored forms so the
	// sweep can look for it without the needle ever being a heap value.
	sealOnce := func(t *testing.T, run func(*MemoryEnclave, func(cipher.AEAD) error) error) (exact, swapped *MemoryEnclave) {
		t.Helper()
		key, err := NewMemoryEnclaveSized(dekBytes)
		if err != nil {
			t.Fatalf("allocating the key: %v", err)
		}
		exact, err = NewMemoryEnclaveSized(dekBytes)
		if err != nil {
			t.Fatalf("allocating a probe: %v", err)
		}
		swapped, err = NewMemoryEnclaveSized(dekBytes)
		if err != nil {
			t.Fatalf("allocating a probe: %v", err)
		}
		if err := key.WithBytes(func(k []byte) error {
			if _, err := rand.Read(k); err != nil {
				return err
			}
			if err := exact.WithBytes(func(e []byte) error { copy(e, k); return nil }); err != nil {
				return err
			}
			return swapped.WithBytes(func(s []byte) error {
				for i := 0; i < len(k); i += 4 {
					s[i], s[i+1], s[i+2], s[i+3] = k[i+3], k[i+2], k[i+1], k[i]
				}
				return nil
			})
		}); err != nil {
			t.Fatalf("filling the key and probes: %v", err)
		}
		// Many operations under the key, each expanding its own schedule:
		// one freed schedule can be overwritten by the next allocation before
		// the sweep reads it (measured: the single-operation control went
		// blind in ~5% of runs), and with 64 the control has to lose every
		// one to go blind — while the claim has to erase every one.
		for range 64 {
			if err := run(key, func(gcm cipher.AEAD) error {
				_ = gcm.Seal(nil, nil, []byte("a real seal under this key"), nil)
				return nil
			}); err != nil {
				t.Fatalf("withAEAD: %v", err)
			}
		}
		// The locked copy is wiped and unmapped: from here the key can only
		// survive in what the AES operation left behind.
		if err := key.Destroy(); err != nil {
			t.Fatalf("destroying the key: %v", err)
		}
		runtime.GC()
		runtime.GC()
		return exact, swapped
	}

	residue := func(t *testing.T, probe *MemoryEnclave) []string {
		t.Helper()
		hits, err := findNeedle(probe)
		if err != nil {
			t.Fatalf("cannot sweep process memory: %v", err)
		}
		var home uintptr
		if err := probe.WithBytes(func(b []byte) error {
			home = uintptr(unsafe.Pointer(unsafe.SliceData(b)))
			return nil
		}); err != nil {
			t.Fatalf("locating the probe: %v", err)
		}
		return rangesOutside(hits, home)
	}

	// CONTROL: without secretDo the schedule survives the GC.
	cExact, cSwapped := sealOnce(t, withAEADErasable)
	defer func() { _ = cExact.Destroy(); _ = cSwapped.Destroy() }()
	if len(residue(t, cExact))+len(residue(t, cSwapped)) == 0 {
		t.Fatal("the control found no key schedule after an UNERASED AES operation: the sweep cannot see " +
			"what this test claims is erased, so the erasure result below would be vacuous")
	}

	// THE CLAIM: through withAEAD, nothing is left.
	exact, swapped := sealOnce(t, withAEAD)
	defer func() { _ = exact.Destroy(); _ = swapped.Destroy() }()
	if hits := append(residue(t, exact), residue(t, swapped)...); len(hits) > 0 {
		t.Fatalf("the key survived an AES operation run under runtime/secret.Do: %d mapping(s) still hold it after GC, first %s", len(hits), hits[0])
	}
}

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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"runtime"
	"testing"
	"unsafe"
)

// TestWithAEAD_ErasesTheKeyScheduleUnderRuntimeSecret pins that an AES
// operation run through withAEAD leaves no copy of its key schedule in memory
// after GC, in either form crypto/aes stores it. The control runs the same
// operation outside secretDo and must find the schedule, so the sweep is not
// vacuous.
func TestWithAEAD_ErasesTheKeyScheduleUnderRuntimeSecret(t *testing.T) {
	if !KeyScheduleErasure() {
		t.Fatal("KeyScheduleErasure() = false in a build constrained to the erasing configuration")
	}

	// sealOnce performs one AES-GCM seal under a fresh random key held in
	// locked memory, through run, and returns probe enclaves holding the key in
	// both stored forms so the needle is never a heap value.
	sealOnce := func(t *testing.T, run func(ByteAccess, func(cipher.AEAD) error) error) (exact, swapped *lockedRegion) {
		t.Helper()
		key, err := newMemorySized(dekBytes)
		if err != nil {
			t.Fatalf("allocating the key: %v", err)
		}
		exact, err = newMemorySized(dekBytes)
		if err != nil {
			t.Fatalf("allocating a probe: %v", err)
		}
		swapped, err = newMemorySized(dekBytes)
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
		// 64 operations, each expanding its own schedule: a single freed
		// schedule can be overwritten before the sweep (the one-operation control
		// went blind in about 5% of runs).
		for range 64 {
			if err := run(key, func(gcm cipher.AEAD) error {
				_ = gcm.Seal(nil, nil, []byte("a real seal under this key"), nil)
				return nil
			}); err != nil {
				t.Fatalf("sealing: %v", err)
			}
		}
		// The locked copy is gone: the key can only survive in what the AES
		// operation left behind.
		if err := key.Destroy(); err != nil {
			t.Fatalf("destroying the key: %v", err)
		}
		runtime.GC()
		runtime.GC()
		return exact, swapped
	}

	residue := func(t *testing.T, probe *lockedRegion) []string {
		t.Helper()
		var home uintptr
		if err := probe.WithBytes(func(b []byte) error {
			home = uintptr(unsafe.Pointer(unsafe.SliceData(b)))
			return nil
		}); err != nil {
			t.Fatalf("locating the probe: %v", err)
		}
		hits, err := findNeedle(probe, home)
		if err != nil {
			t.Fatalf("cannot sweep process memory: %v", err)
		}
		return hits
	}

	// unerased is withAEAD without secretDo: the same key schedule expansion
	// and seal, with nothing to erase what they leave behind.
	unerased := func(key ByteAccess, fn func(cipher.AEAD) error) error {
		return key.WithBytes(func(k []byte) error {
			block, err := aes.NewCipher(k)
			if err != nil {
				return err
			}
			gcm, err := cipher.NewGCMWithRandomNonce(block)
			if err != nil {
				return err
			}
			return fn(gcm)
		})
	}

	// Control: without secretDo the schedule survives the GC.
	cExact, cSwapped := sealOnce(t, unerased)
	defer func() { _ = cExact.Destroy(); _ = cSwapped.Destroy() }()
	if len(residue(t, cExact))+len(residue(t, cSwapped)) == 0 {
		t.Fatal("the control found no key schedule after an UNERASED AES operation: the sweep cannot see " +
			"what this test claims is erased, so the erasure result below would be vacuous")
	}

	// The claim: through withAEAD, nothing is left.
	exact, swapped := sealOnce(t, withAEAD)
	defer func() { _ = exact.Destroy(); _ = swapped.Destroy() }()
	if hits := append(residue(t, exact), residue(t, swapped)...); len(hits) > 0 {
		t.Fatalf("the key survived an AES operation run under runtime/secret.Do: %d mapping(s) still hold it after GC, first %s", len(hits), hits[0])
	}
}

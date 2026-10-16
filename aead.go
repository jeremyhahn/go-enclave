// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"math"
)

// maxSealedPlaintext is AES-GCM's per-message plaintext ceiling. Typed uint64
// because it does not fit in a 32-bit int.
const maxSealedPlaintext uint64 = (1<<32 - 2) * 16

// sealedOverhead is the 12-byte nonce and 16-byte tag AES-GCM with a random
// nonce adds to every sealed message.
const sealedOverhead = 12 + 16

// sealableWithin reports whether n bytes can be sealed in one message on a
// platform whose largest int is maxInt (math.MaxInt here; a parameter so the
// 32-bit bound is testable on a 64-bit host, and without allocating 64 GiB).
func sealableWithin(n, maxInt uint64) error {
	if n > maxSealedPlaintext || n > maxInt-sealedOverhead {
		return ErrMaterialTooLarge
	}
	return nil
}

// randRead is a test seam for a CSPRNG failure, which the standard library
// does not produce on demand.
var randRead = rand.Read

func fillRandom(b []byte) error {
	_, err := randRead(b)
	return err
}

// newKeyEnclave returns a [lockedRegion] holding n bytes from the CSPRNG,
// generated directly into locked memory.
//
//nolint:unparam // n is always 32 today because dekBytes, kekBytes and RootKeyBytes are three independent decisions that happen to agree; folding them into one constant here would couple them.
func newKeyEnclave(n int) (*lockedRegion, error) {
	e, err := newMemorySized(n)
	if err != nil {
		return nil, err
	}
	if err := e.WithBytes(fillRandom); err != nil {
		return nil, destroyOnFailure(&SealError{Cause: err}, e)
	}
	return e, nil
}

// withAEAD runs fn with an AES-GCM AEAD built from the key in key, borrowed
// for the duration of the call. Every AES operation in this package goes
// through here, and it is the only place a key leaves locked memory:
// aes.NewCipher puts the key schedule, whose first round key is the key
// itself, on the heap, where it stays until the memory is reused. Under
// GOEXPERIMENT=runtimesecret the call runs in secretDo and the schedule is
// erased once unreachable ([KeyScheduleErasure]); no cipher.Block or
// cipher.AEAD outlives the call. See docs/sealing/engineering.md,
// "Key-schedule heap exposure".
func withAEAD(key ByteAccess, fn func(cipher.AEAD) error) error {
	var err error
	secretDo(func() {
		err = key.WithBytes(func(k []byte) error {
			block, berr := aes.NewCipher(k)
			if berr != nil {
				return &SealError{Cause: berr}
			}
			// Never fall back to NewGCM: FIPS 140-only mode refuses
			// caller-supplied IVs, and this removes nonce management from
			// callers. It also means GOEXPERIMENT=boringcrypto builds fail
			// here on every seal, by design.
			gcm, gerr := cipher.NewGCMWithRandomNonce(block)
			if gerr != nil {
				return &SealError{Cause: gerr}
			}
			return fn(gcm)
		})
	})
	return err
}

// sealWithKey encrypts plaintext under the key in ke, binding aad, and
// returns nonce || ciphertext || tag as an ordinary heap slice.
func sealWithKey(ke ByteAccess, plaintext, aad []byte) ([]byte, error) {
	if err := sealableWithin(uint64(len(plaintext)), math.MaxInt); err != nil {
		return nil, err
	}

	var sealed []byte
	if err := withAEAD(ke, func(gcm cipher.AEAD) error {
		// A nil nonce is legal only for an AEAD with NonceSize 0; cipher.NewGCM
		// panics on it, so a change of AEAD fails loudly.
		// TestSealed_SealIsNonDeterministic catches an explicit fixed nonce.
		/* #nosec G407 -- nil is required by NewGCMWithRandomNonce, which generates the nonce itself; see above */
		sealed = gcm.Seal(nil, nil, plaintext, aad)
		return nil
	}); err != nil {
		return nil, err
	}
	return sealed, nil
}

// openWithKeyInto decrypts sealed under the key in ke, verifying aad, into
// dst and nowhere else. A plaintext whose length is not exactly len(dst) is
// refused as an authentication failure before decrypting, because a longer
// one would make the AEAD's append reallocate onto the heap.
func openWithKeyInto(ke ByteAccess, sealed, aad, dst []byte) error {
	return withAEAD(ke, func(gcm cipher.AEAD) error {
		return openInto(gcm, sealed, aad, dst)
	})
}

// openInto is openWithKeyInto's body for an AEAD already built, separate so
// its guards can be exercised with an AEAD that misbehaves.
func openInto(gcm cipher.AEAD, sealed, aad, dst []byte) error {
	if len(sealed) <= sealedOverhead || len(sealed)-sealedOverhead != len(dst) {
		return ErrSealedAuthentication
	}

	// dst[:0:len(dst)] pins the capacity so the AEAD's append cannot reallocate.
	// The AEAD may have written into dst before refusing, so every refusal
	// from here wipes dst.
	got, oerr := gcm.Open(dst[:0:len(dst)], nil, sealed, aad)
	if oerr != nil {
		Wipe(dst)
		return ErrSealedAuthentication
	}
	// Residency before length: a result that escaped AND has the wrong length
	// must still have its heap copy wiped.
	if len(got) > 0 && &got[0] != &dst[0] {
		Wipe(got)
		Wipe(dst)
		return ErrPlaintextEscaped
	}
	if len(got) != len(dst) {
		Wipe(dst)
		return ErrSealedAuthentication
	}
	return nil
}

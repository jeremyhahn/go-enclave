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
	"crypto/rand"
	"errors"
	"testing"
)

// FuzzOpenWithKeyInto feeds openWithKeyInto mutated ciphertexts, mutated AADs
// and destinations of every length. It never panics, opens only the one
// payload sealWithKey produced, and refuses everything else with
// ErrSealedAuthentication. A destination of the wrong length is refused before
// anything is decrypted, so it is left untouched; any other refusal leaves dst
// untouched or wiped.
func FuzzOpenWithKeyInto(f *testing.F) {
	key := newWrappingKey(f)
	plaintext := make([]byte, dekBytes)
	if _, err := rand.Read(plaintext); err != nil {
		f.Fatalf("rand.Read: %v", err)
	}
	aad := blobHeader(blobKindDEK, 1)
	sealed, err := sealWithKey(key, plaintext, aad)
	if err != nil {
		f.Fatalf("sealWithKey: %v", err)
	}

	n := uint8(len(plaintext))
	f.Add([]byte(nil), []byte(nil), uint8(0))
	f.Add(sealed, aad, n)
	f.Add(sealed, aad, n-1)
	f.Add(sealed, aad, n+1)
	f.Add(sealed, []byte(nil), n)
	for _, c := range fuzzSeedMutations(sealed) {
		f.Add(c, aad, n)
	}
	for _, c := range fuzzSeedMutations(aad) {
		f.Add(sealed, c, n)
	}

	f.Fuzz(func(t *testing.T, in, inAAD []byte, dstLen uint8) {
		dst := fuzzDestination(int(dstLen))
		err := openWithKeyInto(key, in, inAAD, dst)
		switch {
		case err == nil:
			if !bytes.Equal(dst, plaintext) {
				t.Fatal("openWithKeyInto opened a payload sealWithKey did not produce")
			}
		case !errors.Is(err, ErrSealedAuthentication):
			t.Fatalf("openWithKeyInto = %v, want ErrSealedAuthentication", err)
		case len(in) <= sealedOverhead || len(in)-sealedOverhead != len(dst):
			if !bytes.Equal(dst, fuzzDestination(len(dst))) {
				t.Fatal("openWithKeyInto wrote into a destination of the wrong length")
			}
		case !refusedCleanly(dst):
			t.Fatal("a refused openWithKeyInto left the destination partly written")
		}
	})
}

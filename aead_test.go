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
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"math"
	"reflect"
	"testing"
	"unsafe"
)

// TestSealed_AADRefusesMismatch pins the additional-authenticated-data
// path of the shared AEAD helpers: a message sealed under one AAD must not
// open under another, and must open under its own. Everything the envelope's
// blob-binding claims rests on this behavior;
// TestSealer_EnvelopeBindsBlobToCiphertext exercises it end to end.
func TestSealed_AADRefusesMismatch(t *testing.T) {
	key, err := newKeyEnclave(dekBytes)
	if err != nil {
		t.Fatalf("newKeyEnclave: %v", err)
	}
	defer key.Destroy()

	msg := []byte("aad-bound-message")
	ct, err := sealWithKey(key, msg, []byte("the-sealing-aad"))
	if err != nil {
		t.Fatalf("sealWithKey: %v", err)
	}

	dst := make([]byte, len(msg))
	if err := openWithKeyInto(key, ct, []byte("a-different-aad"), dst); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("open under the wrong AAD = %v, want ErrSealedAuthentication", err)
	}
	if err := openWithKeyInto(key, ct, nil, dst); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("open with the AAD dropped = %v, want ErrSealedAuthentication", err)
	}

	// Control: the right AAD opens, so the refusals above were the AAD's
	// doing.
	if err := openWithKeyInto(key, ct, []byte("the-sealing-aad"), dst); err != nil {
		t.Fatalf("open under the correct AAD: %v", err)
	}
	if !bytes.Equal(dst, msg) {
		t.Error("the AAD-bound message opened to the wrong plaintext")
	}
}

// aesCipherSink defends the allocation measurement below from being optimized
// away; it is never read.
var aesCipherSink cipher.Block

// TestSealed_KeyScheduleReachesTheHeapAsDocumented pins the exposure
// documented in docs/sealing/engineering.md, "Key-schedule heap exposure":
// aes.NewCipher allocates on the heap, and its schedule holds the key either
// byte-exact (hardware path, including fips140=only) or as big-endian uint32
// words (generic path). Offset and layout are not asserted. A failure means
// the documentation needs re-measuring, not that the package is broken.
func TestSealed_KeyScheduleReachesTheHeapAsDocumented(t *testing.T) {
	key := make([]byte, dekBytes)
	for i := range key {
		key[i] = byte(0xA0 + i)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}

	// A crypto/aes that does not return the expanded-schedule struct
	// (BoringCrypto, say) leaves the documented exposure unmeasured, so this fails
	// rather than skips. Every toolchain this repository builds with, including
	// make test-fips, returns the struct.
	v := reflect.ValueOf(block)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		t.Fatalf("crypto/aes returned %T, which is not the expanded-schedule struct this measurement reads: "+
			"the key-schedule exposure withAEAD documents is unmeasured under this toolchain. Re-measure it "+
			"and update the documentation before building with it", block)
	}
	expanded := v.Elem()

	// The claim is about crypto/aes internals, so the test reads them.
	raw := unsafe.Slice((*byte)(unsafe.Pointer(expanded.UnsafeAddr())), expanded.Type().Size())

	swapped := make([]byte, len(key))
	for i := 0; i < len(key); i += 4 {
		swapped[i], swapped[i+1], swapped[i+2], swapped[i+3] = key[i+3], key[i+2], key[i+1], key[i]
	}

	exact, beWords := bytes.Index(raw, key), bytes.Index(raw, swapped)
	switch {
	case exact >= 0:
		t.Logf("master key present BYTE-EXACT at offset %d of the %d-byte expanded schedule (hardware-AES path)", exact, len(raw))
	case beWords >= 0:
		t.Logf("master key present as BIG-ENDIAN WORDS at offset %d of the %d-byte expanded schedule (generic path)", beWords, len(raw))
	default:
		t.Errorf("the master key is in NEITHER form inside the %d-byte expanded AES schedule. "+
			"The documented threat model on withAEAD says it is, and every concession that model makes "+
			"follows from it — re-measure the exposure and rewrite the comment before trusting this suite again", len(raw))
	}

	// And the schedule is a heap allocation rather than a stack temporary: it
	// is returned through the cipher.Block interface, so it escapes. Without
	// this half, the key being in the schedule would say nothing about where
	// the schedule is.
	allocs := testing.AllocsPerRun(100, func() {
		b, cerr := aes.NewCipher(key)
		if cerr != nil {
			t.Fatalf("aes.NewCipher: %v", cerr)
		}
		aesCipherSink = b
	})
	if allocs < 1 {
		t.Errorf("aes.NewCipher allocated %.1f times per call; the documentation says the expanded schedule "+
			"escapes to the heap, and a stack-resident schedule would make the exposure smaller than documented", allocs)
	}
}

// TestSealed_KeysAreDrawnFromTheCSPRNG pins that newKeyEnclave fills
// keys from the CSPRNG. A constant-key mutant survives every envelope test,
// because the random nonce keeps sealed bytes non-deterministic.
func TestSealed_KeysAreDrawnFromTheCSPRNG(t *testing.T) {
	a, err := newKeyEnclave(dekBytes)
	if err != nil {
		t.Fatalf("newKeyEnclave: %v", err)
	}
	defer a.Destroy()
	b, err := newKeyEnclave(dekBytes)
	if err != nil {
		t.Fatalf("newKeyEnclave: %v", err)
	}
	defer b.Destroy()

	if err := a.WithBytes(func(ka []byte) error {
		if holds(b, ka) {
			t.Error("two generated keys are identical; the CSPRNG is not being consulted per key")
		}
		if bytes.Equal(ka, make([]byte, dekBytes)) {
			t.Error("a generated key is all zeroes")
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
}

func TestSealableWithin_BoundsTheSealedLengthByInt(t *testing.T) {
	const maxInt32 = math.MaxInt32
	cases := []struct {
		n, maxInt uint64
		want      error
	}{
		{maxInt32 - sealedOverhead, maxInt32, nil},
		{maxInt32 - sealedOverhead + 1, maxInt32, ErrMaterialTooLarge},
		{maxSealedPlaintext, math.MaxInt64, nil},
		{maxSealedPlaintext + 1, math.MaxInt64, ErrMaterialTooLarge},
	}
	for _, c := range cases {
		if err := sealableWithin(c.n, c.maxInt); !errors.Is(err, c.want) || (c.want == nil && err != nil) {
			t.Errorf("sealableWithin(%d, %d) = %v, want %v", c.n, c.maxInt, err, c.want)
		}
	}
	if err := sealableWithin(maxSealedPlaintext+1, math.MaxInt); !errors.Is(err, ErrMaterialTooLarge) {
		t.Errorf("sealableWithin above the GCM bound = %v, want ErrMaterialTooLarge", err)
	}
}

// fuzzSealMax caps the plaintext FuzzSealOpenRoundTrip seals, to keep each
// iteration cheap; the sizes above it, up to the limit, are covered through
// sealableWithin.
const fuzzSealMax = 64 << 10

// FuzzSealOpenRoundTrip checks that Open(Seal(p)) returns p exactly, through
// one Sealer for the whole target, and that sealableWithin accepts every size
// up to its limit and refuses every size over it with ErrMaterialTooLarge,
// for any int width from 32 to 64 bits.
func FuzzSealOpenRoundTrip(f *testing.F) {
	s, err := newEnvelopeSealer()
	if err != nil {
		f.Fatalf("NewSealer: %v", err)
	}
	f.Cleanup(func() {
		if err := s.Destroy(); err != nil {
			f.Errorf("Sealer.Destroy: %v", err)
		}
	})

	f.Add([]byte("p"), uint64(0), uint64(0))
	f.Add(bytes.Repeat([]byte{0xa5}, 4096), maxSealedPlaintext+1, uint64(math.MaxInt64))
	f.Add([]byte("boundary"), uint64(math.MaxInt32-sealedOverhead+1), uint64(0))
	f.Fuzz(func(t *testing.T, p []byte, n, width uint64) {
		maxInt := uint64(math.MaxInt32) + width%(math.MaxInt64-math.MaxInt32+1)
		limit := min(maxSealedPlaintext, maxInt-sealedOverhead)
		if err := sealableWithin(limit, maxInt); err != nil {
			t.Fatalf("sealableWithin(%d, %d) at the limit = %v, want nil", limit, maxInt, err)
		}
		if err := sealableWithin(limit+1, maxInt); !errors.Is(err, ErrMaterialTooLarge) {
			t.Fatalf("sealableWithin(%d, %d) over the limit = %v, want ErrMaterialTooLarge", limit+1, maxInt, err)
		}
		switch err := sealableWithin(n, maxInt); {
		case n <= limit && err != nil:
			t.Fatalf("sealableWithin(%d, %d) = %v, want nil under the limit %d", n, maxInt, err, limit)
		case n > limit && !errors.Is(err, ErrMaterialTooLarge):
			t.Fatalf("sealableWithin(%d, %d) = %v, want ErrMaterialTooLarge over the limit %d", n, maxInt, err, limit)
		}

		if len(p) > fuzzSealMax {
			p = p[:fuzzSealMax]
		}
		want := bytes.Clone(p)
		v, err := s.sealData(t.Context(), p)
		if len(want) == 0 {
			if !errors.Is(err, ErrEmptyEnclave) {
				t.Fatalf("Seal(empty) = %v, want ErrEmptyEnclave", err)
			}
			return
		}
		if err != nil {
			t.Fatalf("Seal(%d bytes): %v", len(want), err)
		}
		defer func() {
			if err := v.Destroy(); err != nil {
				t.Errorf("Sealed.Destroy: %v", err)
			}
		}()

		m, err := v.Open(t.Context())
		if err != nil {
			t.Fatalf("Open(%d bytes): %v", len(want), err)
		}
		defer func() {
			if err := m.Destroy(); err != nil {
				t.Errorf("Destroy: %v", err)
			}
		}()
		if err := m.WithBytes(func(got []byte) error {
			if !bytes.Equal(got, want) {
				t.Errorf("Open(Seal(p)) = %d bytes differing from p (%d bytes)", len(got), len(want))
			}
			return nil
		}); err != nil {
			t.Fatalf("WithBytes: %v", err)
		}
	})
}

// misbehavingAEAD is an AEAD whose Open does what crypto/cipher never does,
// so the guards in openInto can be reached.
type misbehavingAEAD struct {
	open func(dst, ciphertext []byte) ([]byte, error)
}

func (misbehavingAEAD) NonceSize() int { return 0 }
func (misbehavingAEAD) Overhead() int  { return sealedOverhead }
func (misbehavingAEAD) Seal(dst, _, plaintext, _ []byte) []byte {
	return append(dst, plaintext...)
}

func (m misbehavingAEAD) Open(dst, _, ciphertext, _ []byte) ([]byte, error) {
	return m.open(dst, ciphertext)
}

var _ cipher.AEAD = misbehavingAEAD{}

func TestOpenInto_Guards(t *testing.T) {
	const n = 8
	sealed := make([]byte, n+sealedOverhead)
	mark := func(dst []byte, k int) []byte { return append(dst, bytes.Repeat([]byte{0xAA}, k)...) }
	var escaped []byte

	// Each AEAD writes into dst before it refuses or misreports; the refusal
	// must leave dst wiped.
	cases := map[string]struct {
		open func(dst, ciphertext []byte) ([]byte, error)
		want error
	}{
		"reported failure with full output": {
			open: func(dst, _ []byte) ([]byte, error) { return mark(dst, n), errors.New("tag mismatch") },
			want: ErrSealedAuthentication,
		},
		"plaintext reallocated onto the heap": {
			open: func(dst, _ []byte) ([]byte, error) {
				mark(dst, n-1)
				escaped = bytes.Repeat([]byte{0xAA}, n)
				return escaped, nil
			},
			want: ErrPlaintextEscaped,
		},
		"short plaintext in place": {
			open: func(dst, _ []byte) ([]byte, error) { return mark(dst, n-1), nil },
			want: ErrSealedAuthentication,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dst := fuzzDestination(n)
			if err := openInto(misbehavingAEAD{open: c.open}, sealed, nil, dst); !errors.Is(err, c.want) {
				t.Fatalf("openInto = %v, want %v", err, c.want)
			}
			if !bytes.Equal(dst, make([]byte, n)) {
				t.Fatalf("dst = %x after the refusal, want it wiped", dst)
			}
		})
	}
	if !bytes.Equal(escaped, make([]byte, n)) {
		t.Error("escaped plaintext was not wiped")
	}

	if err := openInto(misbehavingAEAD{}, make([]byte, sealedOverhead), nil, nil); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("openInto of an empty message = %v, want ErrSealedAuthentication", err)
	}
	dst := fuzzDestination(n + 1)
	if err := openInto(misbehavingAEAD{}, sealed, nil, dst); !errors.Is(err, ErrSealedAuthentication) {
		t.Errorf("openInto into a mis-sized destination = %v, want ErrSealedAuthentication", err)
	}
	if !bytes.Equal(dst, fuzzDestination(n+1)) {
		t.Error("openInto wrote a mis-sized destination it refuses before decryption")
	}
}

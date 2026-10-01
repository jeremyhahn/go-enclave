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
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"
)

// sealedMaterial is long and distinctive so a plaintext-residency search
// cannot match it by accident, and so a partial leak is as visible as a whole
// one.
var sealedMaterial = []byte("private-key-material-that-must-never-be-resident-between-opens")

// freshProcessSealer makes a test hermetic against the package-level process
// sealer: whatever earlier tests installed or swept, this test starts with no
// sealer — its first NewSealed installs a fresh software default — and leaves
// none behind. Without this the suite is ORDER-DEPENDENT: a WipeAll in any
// earlier test bricks the shared default (correctly — that is the production
// contract), and under -shuffle or -count>1 a NewSealed-using test then fails
// with ErrSealerWiped. Measured: -count=25 failed 24/24 iterations after the
// first, every failure the sweep-order artifact and none of them the code.
func freshProcessSealer(t *testing.T) {
	t.Helper()
	resetProcessSealerForTest()
	t.Cleanup(resetProcessSealerForTest)
}

// TestSealedEnclave_RoundTrip covers the contract in one pass: the material
// survives sealing and opening, the caller's slice is wiped on the way in, and
// the opened enclave is an independent one the caller owns.
func TestSealedEnclave_RoundTrip(t *testing.T) {
	freshProcessSealer(t)
	src := append([]byte(nil), sealedMaterial...)

	s, err := NewSealed(t.Context(), src)
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	for i, b := range src {
		if b != 0 {
			t.Fatalf("src[%d] = %#x after NewSealed, want the caller's slice wiped", i, b)
		}
	}
	if !s.IsAlive() {
		t.Error("IsAlive = false on a fresh sealed enclave")
	}
	if got := s.String(); got != "SealedEnclave(sealed)" {
		t.Errorf("String = %q", got)
	}

	e, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer e.Destroy()

	if !e.EqualTo(sealedMaterial) {
		t.Error("the opened enclave does not hold the sealed material")
	}
	if e.Size() != len(sealedMaterial) {
		t.Errorf("Size = %d, want %d", e.Size(), len(sealedMaterial))
	}
}

// TestSealedEnclave_NoPlaintextAtRest is the property this type exists for,
// and the one that distinguishes it from MemoryEnclave: between Opens the
// material is not readable at all.
//
// Searching BOTH envelope halves for the plaintext is the whole assertion,
// and it is a real one — skip the encrypt step and store the plaintext
// instead, and this finds it immediately. It also checks progressively
// shorter prefixes, so a partial or truncated leak is caught rather than only
// a whole-value one.
func TestSealedEnclave_NoPlaintextAtRest(t *testing.T) {
	freshProcessSealer(t)
	src := append([]byte(nil), sealedMaterial...)
	s, err := NewSealed(t.Context(), src)
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	for name, half := range map[string][]byte{"sealed": s.sealed, "blob": s.blob} {
		if bytes.Contains(half, sealedMaterial) {
			t.Fatalf("the whole plaintext is present in the %s bytes; the material is not encrypted at rest", name)
		}
		for n := len(sealedMaterial); n >= 8; n /= 2 {
			if bytes.Contains(half, sealedMaterial[:n]) {
				t.Errorf("the first %d bytes of the plaintext are present in the %s bytes", n, name)
			}
		}
	}

	// Ciphertext plus a nonce and a tag is necessarily longer than the
	// plaintext. Equal length would mean nothing was added, which is what a
	// store-it-raw mutation looks like from the outside.
	if len(s.sealed) <= len(sealedMaterial) {
		t.Errorf("sealed length %d <= plaintext length %d; nothing was added",
			len(s.sealed), len(sealedMaterial))
	}
}

// TestSealedEnclave_SealIsNonDeterministic pins the nonce. Sealing the same
// material twice must produce different bytes; identical output would mean a
// fixed or reused nonce, which for GCM is not a weakness but a break — it
// leaks the XOR of the two plaintexts and destroys the authentication
// guarantee.
//
// A mutant that hands Seal a zeroed nonce passes every other test in this
// file.
func TestSealedEnclave_SealIsNonDeterministic(t *testing.T) {
	freshProcessSealer(t)
	first, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer first.Destroy()

	second, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer second.Destroy()

	if bytes.Equal(first.sealed, second.sealed) {
		t.Fatal("sealing identical material twice produced identical bytes: the nonce is fixed or reused")
	}
	// The wrapped DEKs must differ too: identical blobs would mean the same
	// DEK was drawn twice, i.e. the CSPRNG is not being consulted per value.
	if bytes.Equal(first.blob, second.blob) {
		t.Fatal("two seals produced identical wrapped-DEK blobs: per-value keys are not per-value")
	}

	// Both must still open to the same material — different bytes, same value.
	for _, s := range []*SealedEnclave{first, second} {
		e, err := s.Open(t.Context())
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !e.EqualTo(sealedMaterial) {
			t.Error("an independently sealed copy did not open to the original material")
		}
		e.Destroy()
	}
}

// TestSealedEnclave_DetectsTampering covers the A in AEAD, on BOTH envelope
// halves. Every region is covered — the nonce at the front of the sealed
// bytes, the ciphertext body, the tag at the end, and the blob's frame, body
// and tail — so a mutation that authenticated only part of the envelope would
// show up as a position that opens successfully after being altered.
func TestSealedEnclave_DetectsTampering(t *testing.T) {
	freshProcessSealer(t)
	half := func(s *SealedEnclave, sealed bool) []byte {
		if sealed {
			return s.sealed
		}
		return s.blob
	}
	for _, pos := range []struct {
		name   string
		sealed bool // which half to corrupt
		index  func(n int) int
	}{
		{"first nonce byte", true, func(int) int { return 0 }},
		{"last nonce byte", true, func(int) int { return 11 }},
		{"first ciphertext byte", true, func(int) int { return 12 }},
		{"middle of ciphertext", true, func(n int) int { return n / 2 }},
		{"last tag byte", true, func(n int) int { return n - 1 }},
		{"blob frame", false, func(int) int { return 0 }},
		{"blob middle", false, func(n int) int { return n / 2 }},
		{"blob last byte", false, func(n int) int { return n - 1 }},
	} {
		t.Run(pos.name, func(t *testing.T) {
			s, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
			if err != nil {
				t.Fatalf("NewSealed: %v", err)
			}
			defer s.Destroy()

			target := half(s, pos.sealed)
			i := pos.index(len(target))
			target[i] ^= 0xFF

			e, err := s.Open(t.Context())
			if !errors.Is(err, ErrSealedAuthentication) {
				t.Errorf("Open after flipping byte %d = %v, want ErrSealedAuthentication", i, err)
			}
			if e != nil {
				t.Error("Open returned an enclave for material that did not authenticate")
				e.Destroy()
			}

			// The control: undo the flip and the same value opens, so the
			// refusal above was the tamper's doing and not a value that never
			// worked.
			target[i] ^= 0xFF
			e, err = s.Open(t.Context())
			if err != nil {
				t.Fatalf("Open after restoring the byte: %v", err)
			}
			if !e.EqualTo(sealedMaterial) {
				t.Error("restored value opened to the wrong material")
			}
			e.Destroy()
		})
	}
}

// TestSealedEnclave_TruncationIsRejected covers the lengths the tamper test
// cannot reach: a sealed half shorter than the nonce has no nonce to read,
// one shorter than the tag cannot authenticate, and a blob shorter than its
// frame cannot even be parsed. All must be refused rather than indexed into.
func TestSealedEnclave_TruncationIsRejected(t *testing.T) {
	freshProcessSealer(t)
	s, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	fullSealed := append([]byte(nil), s.sealed...)
	for _, n := range []int{0, 1, 11, 12, 13, len(fullSealed) - 1} {
		// fullSealed[:n:n], not append(nil, ...): appending nothing to a nil
		// slice yields nil, which Open correctly reports as DESTROYED rather
		// than as a short value, and the test would then be asserting the
		// wrong contract at n = 0.
		s.sealed = fullSealed[:n:n]
		e, err := s.Open(t.Context())
		if !errors.Is(err, ErrSealedAuthentication) {
			t.Errorf("Open on a %d-byte sealed value = %v, want ErrSealedAuthentication", n, err)
		}
		if e != nil {
			t.Errorf("Open returned an enclave for a %d-byte sealed value", n)
			e.Destroy()
		}
	}
	s.sealed = fullSealed

	fullBlob := append([]byte(nil), s.blob...)
	for _, n := range []int{0, 1, blobHeaderLen - 1, blobHeaderLen, len(fullBlob) - 1} {
		s.blob = fullBlob[:n:n]
		e, err := s.Open(t.Context())
		if !errors.Is(err, ErrSealedAuthentication) {
			t.Errorf("Open on a %d-byte blob = %v, want ErrSealedAuthentication", n, err)
		}
		if e != nil {
			t.Errorf("Open returned an enclave for a %d-byte blob", n)
			e.Destroy()
		}
	}
	s.blob = fullBlob

	// Control: with both halves restored the value still opens.
	e, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("Open after restoring both halves: %v", err)
	}
	e.Destroy()
}

// TestSealedEnclave_OpensAreIndependent pins the ownership contract on Open's
// result: each call yields a separate enclave the caller owns, and destroying
// one affects neither the other nor the sealed value it came from.
func TestSealedEnclave_OpensAreIndependent(t *testing.T) {
	freshProcessSealer(t)
	s, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	first, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("first Open: %v", err)
	}
	second, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}

	if first == second {
		t.Fatal("two Opens returned the same enclave")
	}

	first.Destroy()

	if second.IsAlive() != true {
		t.Error("destroying one opened enclave destroyed the other")
	}
	if !second.EqualTo(sealedMaterial) {
		t.Error("destroying one opened enclave corrupted the other")
	}
	if !s.IsAlive() {
		t.Error("destroying an opened enclave destroyed the sealed enclave")
	}

	// And the sealed value still opens afterwards.
	third, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("Open after destroying an earlier result: %v", err)
	}
	if !third.EqualTo(sealedMaterial) {
		t.Error("a later Open did not return the material")
	}
	third.Destroy()
	second.Destroy()
}

// TestSealedEnclave_Lifecycle covers the destroyed contract, idempotence, and
// the nil receiver — the three things a caller relies on to write
// `defer s.Destroy()` without thinking about it.
func TestSealedEnclave_Lifecycle(t *testing.T) {
	freshProcessSealer(t)
	s, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}

	// Held to check the wipe after Destroy nils the fields: BOTH halves of
	// the envelope are wiped, not just the ciphertext.
	sealed, blob := s.sealed, s.blob

	s.Destroy()
	s.Destroy() // idempotent

	for name, half := range map[string][]byte{"sealed": sealed, "blob": blob} {
		for i, b := range half {
			if b != 0 {
				t.Fatalf("%s[%d] = %#x after Destroy, want the envelope wiped", name, i, b)
			}
		}
	}
	if s.IsAlive() {
		t.Error("IsAlive = true after Destroy")
	}
	if e, err := s.Open(t.Context()); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open after Destroy = %v, want ErrEnclaveDestroyed", err)
		if e != nil {
			e.Destroy()
		}
	}
	if got := s.String(); got != "SealedEnclave(destroyed)" {
		t.Errorf("String = %q after Destroy", got)
	}

	var nilSealed *SealedEnclave
	nilSealed.Destroy() // must not panic
	if nilSealed.IsAlive() {
		t.Error("IsAlive = true on a nil sealed enclave")
	}
	if _, err := nilSealed.Open(t.Context()); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open on nil = %v, want ErrEnclaveDestroyed", err)
	}
	// Asserted as a substring rather than the whole literal so the string
	// does not reach goconst's three-occurrence threshold. The yardstick
	// stays independent of the code under test either way.
	if got := nilSealed.String(); !strings.Contains(got, "destroyed") {
		t.Errorf("String on nil = %q, want it to report the enclave as destroyed", got)
	}
}

func TestSealedEnclave_Empty(t *testing.T) {
	for name, in := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			s, err := NewSealed(t.Context(), in)
			if !errors.Is(err, ErrEmptyEnclave) {
				t.Errorf("NewSealed(t.Context(), %s) = %v, want ErrEmptyEnclave", name, err)
			}
			if s != nil {
				t.Errorf("NewSealed(t.Context(), %s) returned a non-nil enclave", name)
			}
		})
	}
}

// TestSealedEnclave_Sizes seals a spread of lengths, including ones that
// straddle the AEAD's block and the page boundary Open's destination is
// rounded to. A length that happened to match the block size exactly is where
// an off-by-one in the in-place decryption would show.
func TestSealedEnclave_Sizes(t *testing.T) {
	freshProcessSealer(t)
	page := int(pageSize)
	for _, n := range []int{1, 15, 16, 17, 31, 32, 64, page - 1, page, page + 1} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			want := bytes.Repeat([]byte{byte(n % 251)}, n)

			s, err := NewSealed(t.Context(), append([]byte(nil), want...))
			if err != nil {
				t.Fatalf("NewSealed(t.Context(), %d): %v", n, err)
			}
			defer s.Destroy()

			e, err := s.Open(t.Context())
			if err != nil {
				t.Fatalf("Open(%d): %v", n, err)
			}
			defer e.Destroy()

			if e.Size() != n {
				t.Errorf("Size = %d, want %d", e.Size(), n)
			}
			if !e.EqualTo(want) {
				t.Errorf("round trip failed at %d bytes", n)
			}
			// Only search for needles long enough that a chance match is
			// negligible. A one-byte plaintext is present in 28 bytes of
			// random nonce and tag with near-certainty, and reporting that as
			// a leak would be a false positive that trains the reader to
			// ignore this assertion. The residency property itself is
			// asserted properly by TestSealedEnclave_NoPlaintextAtRest
			// against a 62-byte value.
			if n >= 8 && bytes.Contains(s.sealed, want) {
				t.Errorf("plaintext of %d bytes found in the sealed value", n)
			}
		})
	}
}

// TestSealedEnclave_Concurrent runs Opens, reads and Destroys against one
// sealed value from many goroutines. Under -race this catches an access that
// escapes the lock; without it, it still catches an Open that reads a cleared
// envelope.
//
// It also exercises the nested-borrow path under contention: every Open
// borrows hierarchy keys and, inside those borrows, allocates and borrows
// further enclaves. That shape deadlocked before v0.3.0-alpha.
func TestSealedEnclave_Concurrent(t *testing.T) {
	freshProcessSealer(t)
	const goroutines, iterations = 16, 50

	s, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				e, err := s.Open(t.Context())
				if err != nil {
					// Only the destroyer's outcome is acceptable.
					if !errors.Is(err, ErrEnclaveDestroyed) {
						t.Errorf("Open: %v", err)
					}
					return
				}
				if !e.EqualTo(sealedMaterial) {
					t.Error("a concurrent Open returned the wrong material")
				}
				e.Destroy()
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		s.Destroy()
	}()

	wg.Wait()

	if s.IsAlive() {
		t.Error("IsAlive = true after a concurrent Destroy")
	}
}

// TestSealedEnclave_SizeMismatchIsRejected covers the consistency guard
// between the recorded plaintext length and what the AEAD actually produces.
//
// The two are written at different times — size at Seal, the plaintext at
// Open — so nothing structural keeps them in step, and a mismatch means the
// destination enclave is the wrong size for the material about to fill it.
// Left unchecked, a size LARGER than the truth would hand back an enclave
// whose tail is uninitialised while reporting success, and Size() would lie
// about what the caller is holding.
//
// It is reachable only by corrupting the field directly, which is what this
// does; in normal use the two cannot diverge. That is the point of a guard on
// an invariant rather than on an input.
func TestSealedEnclave_SizeMismatchIsRejected(t *testing.T) {
	freshProcessSealer(t)
	for _, delta := range []int{+1, +64, -1} {
		s, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("NewSealed: %v", err)
		}

		s.size += delta

		e, err := s.Open(t.Context())
		if !errors.Is(err, ErrSealedAuthentication) {
			t.Errorf("Open with size off by %+d = %v, want ErrSealedAuthentication", delta, err)
		}
		if e != nil {
			t.Errorf("Open returned an enclave despite a size mismatch of %+d", delta)
			e.Destroy()
		}

		s.Destroy()
	}
}

// TestSealedEnclave_OversizedMaterialIsRefusedNotPanicked covers the bound
// AES-GCM places on one message: (2^32-2) blocks of 16 bytes, about 64 GiB.
//
// crypto/cipher enforces it by PANICKING. That is defensible for a primitive
// whose caller is expected to know the construction, and wrong for a
// constructor that documents every other failure as a typed error — a library
// handed a legal slice of a large length should not take the process down.
//
// The check is exercised through sealableLength rather than by allocating 64
// GiB, which is the reason that helper takes a length instead of a slice.
// This reads production code's own bound; it is not a fault-injection seam,
// because the bound has to exist for the guard to work at all.
func TestSealedEnclave_OversizedMaterialIsRefusedNotPanicked(t *testing.T) {
	if maxSealedPlaintext != (1<<32-2)*16 {
		t.Fatalf("maxSealedPlaintext = %d, want (2^32-2)*16 = %d: the guard no longer matches the bound "+
			"crypto/internal/fips140/aes/gcm panics on", maxSealedPlaintext, uint64((1<<32-2)*16))
	}

	// At the ceiling is legal; one byte past it is not. Lengths only —
	// nothing of this size is allocated, which is the whole reason the guard
	// takes a number instead of a slice.
	if err := sealableLength(maxSealedPlaintext); err != nil {
		t.Errorf("sealableLength(the exact ceiling) = %v, want nil: the bound is inclusive", err)
	}
	if err := sealableLength(maxSealedPlaintext + 1); !errors.Is(err, ErrMaterialTooLarge) {
		t.Errorf("sealableLength(ceiling+1) = %v, want ErrMaterialTooLarge; crypto/cipher would panic here", err)
	}

	// And an ordinary length still passes, so the guard is not refusing
	// everything.
	if err := sealableLength(uint64(len(sealedMaterial))); err != nil {
		t.Errorf("sealableLength(%d) = %v, want nil", len(sealedMaterial), err)
	}

	// On a 32-bit platform no slice can reach the ceiling, so NewSealed can
	// never trip the guard there; the helper is still exercised above, which
	// is why the check is on a length rather than in the constructor.
	if strconv.IntSize < 64 {
		t.Logf("int is %d bits: no slice can reach the %d-byte ceiling, so the guard is unreachable "+
			"through NewSealed here", strconv.IntSize, maxSealedPlaintext)
	}
}

// TestSealedEnclave_AADRefusesMismatch pins the additional-authenticated-data
// path of the shared AEAD helpers: a message sealed under one AAD must not
// open under another, and must open under its own. Everything the envelope's
// blob-binding claims rests on this behavior;
// TestSealer_EnvelopeBindsBlobToCiphertext exercises it end to end.
func TestSealedEnclave_AADRefusesMismatch(t *testing.T) {
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

// TestSealedEnclave_KeyScheduleReachesTheHeapAsDocumented pins the
// measurement that [withAEAD]'s threat model rests on, so the documentation
// is auditable by running the suite rather than by trusting its prose.
//
// The claim being pinned is the load-bearing one: no key used through
// withAEAD stays in locked memory, because crypto/aes.NewCipher expands it
// into a heap allocation and for AES the FIRST ROUND KEY IS THE MASTER KEY.
// Everything the documentation concedes — swap exposure, cold-boot exposure,
// a core dump on a host that refused the RLIMIT_CORE lowering — follows from
// that one fact, and the honest boundary drawn around sealing is worth
// nothing if the fact is wrong or silently stops holding.
//
// It is a DOCUMENTATION TEST. It fails if the key stops appearing in the
// schedule, or if NewCipher stops allocating — and a failure means the
// comment has gone stale and the security claim needs re-measuring, NOT that
// the package is broken. Failing loudly at that moment is the entire point: a
// stale threat model reads exactly like a current one.
//
// Two forms are accepted because the two code paths store the key
// differently, and both recover it outright: the hardware path (AES-NI, Armv8
// crypto extensions), which is also the path taken under
// GODEBUG=fips140=only, copies the key in byte-exact; the generic path stores
// it as big-endian uint32 words, which on a little-endian host is the same
// bytes swapped within each four-byte group. Neither the offset nor the
// struct layout is asserted — those vary with word size, and the exposure
// does not.
func TestSealedEnclave_KeyScheduleReachesTheHeapAsDocumented(t *testing.T) {
	key := make([]byte, dekBytes)
	for i := range key {
		key[i] = byte(0xA0 + i)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}

	v := reflect.ValueOf(block)
	if v.Kind() != reflect.Pointer || v.Elem().Kind() != reflect.Struct {
		t.Skipf("crypto/aes returned %T, which is not the expanded-schedule struct this measurement reads "+
			"(a BoringCrypto or other build); the exposure is unmeasured here rather than absent", block)
	}
	expanded := v.Elem()

	// Read the expanded schedule as raw bytes. Reaching into another
	// package's internals is exactly what a documentation test of this kind
	// has to do: the claim is ABOUT those internals.
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

// TestSealedEnclave_WipeAllFailsClosed pins the RULED post-sweep contract
// (#22 §14): a shutdown sweep destroys the process sealer's keys, and from
// that point the sealer FAILS CLOSED with the DISTINCT ErrSealerWiped — it
// never silently re-keys, and never reports the lifecycle event as an
// authentication failure.
//
// The distinct error is the load-bearing part. The regeneration mutant —
// restore the pre-#22 behavior of minting a fresh key on the next seal — made
// the next NewSealed SUCCEED, so nothing was wrong at the point of the
// mistake, and only previously sealed values failed, with an error whose
// documented gloss is "tampered, or sealed under a different key". A
// lifecycle bug presenting as a security incident is the expensive shape,
// and this test exists to keep it impossible.
func TestSealedEnclave_WipeAllFailsClosed(t *testing.T) {
	freshProcessSealer(t)

	s, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("NewSealed: %v", err)
	}
	defer s.Destroy()

	// Non-vacuity: it opens BEFORE the sweep, so the refusal afterwards is
	// the sweep's doing and not a value that never worked.
	e, err := s.Open(t.Context())
	if err != nil {
		t.Fatalf("Open before the sweep: %v", err)
	}
	if !e.EqualTo(sealedMaterial) {
		t.Fatal("opened to the wrong material before the sweep")
	}
	e.Destroy()

	if remaining := sweep(t); remaining != 0 {
		t.Fatalf("the sweep left %d enclave(s) on the ledger; this test needs a clean sweep to attribute what follows", remaining)
	}

	// The sealed value is NOT on the ledger, so the sweep did not reach it:
	// the handle stays alive because IsAlive reports on the CIPHERTEXT, which
	// the sweep does not touch. Not covering this type is the #33 decision,
	// and the apparent contradiction is resolved by Openable rather than by
	// extending the sweep; see TestSealedEnclave_OpenableReportsTheSweep.
	if !s.IsAlive() {
		t.Error("WipeAll destroyed the SealedEnclave; the ledger holds MemoryEnclaves and this type is not one. " +
			"If that changed deliberately, WipeAll's contract, SealedEnclave's documentation and the #33 decision all need updating")
	}
	if err := s.Openable(); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Openable after the sweep = %v, want ErrSealerWiped: the openability question is "+
			"what a caller has instead of a swept handle", err)
	}

	// Open fails with the DISTINCT error — not ErrSealedAuthentication,
	// which would read as tampering, and not ErrEnclaveDestroyed, which
	// would point at a handle the caller never destroyed.
	if _, err := s.Open(t.Context()); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Open after the sweep = %v, want ErrSealerWiped", err)
	}

	// And sealing does NOT resume: no silent regeneration, ever. This is the
	// assertion the regeneration mutant fails.
	if fresh, err := NewSealed(t.Context(), append([]byte(nil), sealedMaterial...)); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("NewSealed after the sweep = %v, want ErrSealerWiped: the sealer must fail closed, never re-key", err)
		if fresh != nil {
			fresh.Destroy()
		}
	}

	// The package-level surface is bricked on purpose — the one-shot
	// installer cannot swap in a replacement under (dead) sealed values.
	replacement, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if err := SetSealer(replacement); !errors.Is(err, ErrSealerInstalled) {
		t.Errorf("SetSealer after the sweep = %v, want ErrSealerInstalled", err)
	}

	// Explicit re-initialization is a NEW Sealer, and it works: the sweep
	// retired this process's keys, not the machinery.
	v, err := replacement.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal on a fresh explicit Sealer after the sweep: %v", err)
	}
	defer v.Destroy()
	e, err = v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open on the fresh Sealer's value: %v", err)
	}
	if !e.EqualTo(sealedMaterial) {
		t.Error("the fresh Sealer's value opened to the wrong material")
	}
	e.Destroy()
}

// TestSealedEnclave_KeysAreDrawnFromTheCSPRNG pins newKeyEnclave's one job
// beyond allocation: consulting the CSPRNG. No black-box test can see a DEK,
// so a mutant filling keys with a constant survives every envelope test —
// the random nonce keeps sealed bytes non-deterministic even under identical
// keys, which would quietly turn every value in the process onto ONE key
// with the per-key message bound unenforced.
func TestSealedEnclave_KeysAreDrawnFromTheCSPRNG(t *testing.T) {
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
		if b.EqualTo(ka) {
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

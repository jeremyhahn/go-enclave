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
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// sealedMaterial is long and distinctive so a plaintext-residency search
// cannot match it by accident, and so a partial leak is as visible as a whole
// one.
var sealedMaterial = []byte("private-key-material-that-must-never-be-resident-between-opens")

// freshProcessSealer starts the test with no process sealer and leaves none
// behind. The process sealer is one-shot and a WipeAll in an earlier test
// bricks it, so without this a later NewSealed fails with ErrSealerWiped under
// -shuffle or -count>1.
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

	if !holds(e, sealedMaterial) {
		t.Error("the opened enclave does not hold the sealed material")
	}
	if e.Size() != len(sealedMaterial) {
		t.Errorf("Size = %d, want %d", e.Size(), len(sealedMaterial))
	}
}

// TestSealedEnclave_NoPlaintextAtRest pins that between Opens the material is
// not readable: neither envelope half contains the plaintext or any long
// prefix of it.
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

// TestSealedEnclave_SealIsNonDeterministic pins the nonce: sealing the same
// material twice must produce different bytes, since a repeated GCM nonce is a
// break. A zeroed-nonce mutant passes every other test in this file.
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
		if !holds(e, sealedMaterial) {
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
			if !holds(e, sealedMaterial) {
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
		// fullSealed[:n:n], not append(nil, ...): at n = 0 the latter is nil, which
		// Open reports as destroyed rather than short.
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
	if !holds(second, sealedMaterial) {
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
	if !holds(third, sealedMaterial) {
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
	// A substring keeps the literal below goconst's threshold.
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
			if !holds(e, want) {
				t.Errorf("round trip failed at %d bytes", n)
			}
			// Skip needles short enough to occur by chance in the 28 bytes of nonce
			// and tag; TestSealedEnclave_NoPlaintextAtRest covers residency.
			if n >= 8 && bytes.Contains(s.sealed, want) {
				t.Errorf("plaintext of %d bytes found in the sealed value", n)
			}
		})
	}
}

// TestSealedEnclave_Concurrent runs Opens, reads and Destroys against one
// sealed value from many goroutines. Under -race it catches an access that
// escapes the lock; without it, an Open that reads a cleared envelope. It also
// exercises nested borrows under contention.
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
				if !holds(e, sealedMaterial) {
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

// TestSealedEnclave_SizeMismatchIsRejected pins the guard between the
// recorded plaintext length and what the AEAD produces. The two cannot diverge
// in normal use, so the test corrupts the field directly.
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

// TestSealedEnclave_OversizedMaterialIsRefusedNotPanicked pins that AES-GCM's
// per-message bound, which crypto/cipher enforces by panicking, arrives as
// ErrMaterialTooLarge. It passes lengths to sealableLength rather than
// allocating 64 GiB.
func TestSealedEnclave_OversizedMaterialIsRefusedNotPanicked(t *testing.T) {
	if maxSealedPlaintext != (1<<32-2)*16 {
		t.Fatalf("maxSealedPlaintext = %d, want (2^32-2)*16 = %d: the guard no longer matches the bound "+
			"crypto/internal/fips140/aes/gcm panics on", maxSealedPlaintext, uint64((1<<32-2)*16))
	}

	// At the ceiling is legal; one byte past it is not.
	if err := sealableWithin(maxSealedPlaintext, math.MaxInt); err != nil {
		t.Errorf("sealableWithin(the exact ceiling) = %v, want nil: the bound is inclusive", err)
	}
	if err := sealableWithin(maxSealedPlaintext+1, math.MaxInt); !errors.Is(err, ErrMaterialTooLarge) {
		t.Errorf("sealableWithin(ceiling+1) = %v, want ErrMaterialTooLarge; crypto/cipher would panic here", err)
	}

	// And an ordinary length still passes, so the guard is not refusing
	// everything.
	if err := sealableWithin(uint64(len(sealedMaterial)), math.MaxInt); err != nil {
		t.Errorf("sealableWithin(%d) = %v, want nil", len(sealedMaterial), err)
	}

	// On a 32-bit platform no slice can reach the ceiling; the helper is still
	// covered above.
	if strconv.IntSize < 64 {
		t.Logf("int is %d bits: no slice can reach the %d-byte ceiling, so the guard is unreachable "+
			"through NewSealed here", strconv.IntSize, maxSealedPlaintext)
	}
}

func TestEnclaves_GoStringIsRedacted(t *testing.T) {
	ctx := t.Context()
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	t.Cleanup(func() { _ = s.Destroy() })
	v, err := s.Seal(ctx, []byte("gostring-material"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if got := fmt.Sprintf("%#v", v); got != "SealedEnclave(sealed)" {
		t.Errorf("%%#v of a SealedEnclave = %q, want the redacted form", got)
	}
	e, err := v.Open(ctx)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got := fmt.Sprintf("%#v", e); got != "MemoryEnclave(redacted)" {
		t.Errorf("%%#v of a MemoryEnclave = %q, want the redacted form", got)
	}
	_ = e.Destroy()
	v.Destroy()
	if got := fmt.Sprintf("%#v", v); got != "SealedEnclave(destroyed)" {
		t.Errorf("%%#v of a destroyed SealedEnclave = %q", got)
	}
}

// TestSealedEnclave_WipeAllFailsClosed pins the post-sweep contract: a
// shutdown sweep destroys the process sealer's keys, and from then on the
// sealer fails with the distinct ErrSealerWiped. It never re-keys, which would
// let new seals succeed while old values failed as ErrSealedAuthentication.
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
	if !holds(e, sealedMaterial) {
		t.Fatal("opened to the wrong material before the sweep")
	}
	e.Destroy()

	if remaining := sweep(t); remaining != 0 {
		t.Fatalf("the sweep left %d enclave(s) on the ledger; this test needs a clean sweep to attribute what follows", remaining)
	}

	// The sweep does not touch sealed values, so IsAlive (which reports on the
	// ciphertext) stays true; Openable reports the sweep instead.
	if !s.IsAlive() {
		t.Error("WipeAll destroyed the SealedEnclave; the ledger holds MemoryEnclaves and this type is not one. " +
			"If that changed deliberately, WipeAll's contract, SealedEnclave's documentation and the decision not to sweep sealed values all need updating")
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
	if !holds(e, sealedMaterial) {
		t.Error("the fresh Sealer's value opened to the wrong material")
	}
	e.Destroy()
}

// sweepForOpenableTest runs a [WipeAll] inside freshProcessSealer, so later
// tests calling [NewSealed] do not inherit a swept one-shot process sealer.
func sweepForOpenableTest(t *testing.T) {
	t.Helper()
	freshProcessSealer(t)
	sweep(t)
}

// TestSealedEnclave_OpenableReportsTheSweep pins that a sweep leaves a sealed
// value reporting IsAlive (its ciphertext is untouched) while Openable reports
// ErrSealerWiped, in agreement with Open.
func TestSealedEnclave_OpenableReportsTheSweep(t *testing.T) {
	s, err := NewSealer() // software provider, ModeRootKey
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	// Non-vacuity: openable BEFORE the sweep, so what follows is the sweep's
	// doing and not a value that was never openable.
	if err := v.Openable(); err != nil {
		t.Fatalf("Openable before the sweep = %v, want nil", err)
	}
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open before the sweep: %v", err)
	}
	e.Destroy()

	sweepForOpenableTest(t)

	// IsAlive is unchanged: it reports on the ciphertext, which is still here.
	if !v.IsAlive() {
		t.Error("the sweep destroyed the SealedEnclave; the ledger holds MemoryEnclaves and this " +
			"type is not one. If that changed deliberately, WipeAll's contract, SealedEnclave's " +
			"documentation and the decision not to sweep sealed values all need updating")
	}

	// And Openable is the one that moved.
	if err := v.Openable(); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Openable after the sweep = %v, want ErrSealerWiped: a value that cannot be "+
			"opened must say so, or IsAlive is the only signal and it reports the wrong thing", err)
	}

	// It agrees with what an actual Open does, which is the property that
	// makes it worth calling at all.
	if _, err := v.Open(t.Context()); !errors.Is(err, ErrSealerWiped) {
		t.Errorf("Open after the sweep = %v, want ErrSealerWiped", err)
	}
}

// TestSealedEnclave_OpenableSeparatesASweepFromADestroy pins that a swept
// value reports ErrSealerWiped, distinguishable from a destroyed value's
// ErrEnclaveDestroyed.
func TestSealedEnclave_OpenableSeparatesASweepFromADestroy(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	swept, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer swept.Destroy()

	destroyed, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
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
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
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

// TestSealedEnclave_OpenableSplitsByMode pins Openable in ModePerOperation
// after a sweep: nil for a provider whose key lives outside the process (the
// value really opens), ErrSealerWiped for the software provider, whose root is
// an in-process enclave.
func TestSealedEnclave_OpenableSplitsByMode(t *testing.T) {
	t.Run("deviceHeldKeySurvivesTheSweep", func(t *testing.T) {
		// The provider reports its health, so its answer overrides the
		// sweep-generation fallback; compare reportsNothingAfterASweep below.
		s, err := NewSealer(
			WithKeyProtector(healthyProtector{newMapKeyProtector(t)}),
		)
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
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
		e, err := v.Open(t.Context())
		if err != nil {
			t.Fatalf("Open after a sweep with a device-held key = %v; Openable said nil, so one "+
				"of the two is wrong", err)
		}
		if !holds(e, sealedMaterial) {
			t.Error("post-sweep open returned the wrong material")
		}
		e.Destroy()
	})

	t.Run("softwareProviderRootDoesNot", func(t *testing.T) {
		s, err := NewSealer(WithKeyProtector(NewSoftwareProvider()))
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		if err := v.Openable(); err != nil {
			t.Fatalf("Openable before the sweep = %v, want nil", err)
		}

		sweepForOpenableTest(t)

		// The software provider's root is an in-process enclave, so Openable must
		// report the sweep.
		if err := v.Openable(); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Openable after the sweep = %v, want ErrSealerWiped: the software provider's "+
				"root is an in-process enclave and the sweep destroyed it", err)
		}
		if _, err := v.Open(t.Context()); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Open after the sweep = %v, want ErrSealerWiped", err)
		}
	})
}

// TestWipeAll_DoesNotSweepSealedEnclaves pins that WipeAll's count excludes
// sealed values: they hold no locked memory; the sealer's keys do.
func TestWipeAll_DoesNotSweepSealedEnclaves(t *testing.T) {
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	const n = 5
	values := make([]*SealedEnclave, 0, n)
	for i := 0; i < n; i++ {
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
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

	// A second sweep with sealed values still live reports zero.
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

// TestSealedEnclave_OpenableClosesTheExternalProviderFailOpen pins that a
// provider without HealthReporter, whose in-process key a sweep destroyed,
// gets ErrOpenabilityUnknown from Openable rather than nil.
func TestSealedEnclave_OpenableClosesTheExternalProviderFailOpen(t *testing.T) {
	p := newEnclaveBackedProtector(t)

	// Premise: this provider reports no health.
	if _, ok := interface{}(p).(HealthReporter); ok {
		t.Fatal("provider satisfies HealthReporter; it no longer stands in for one that reports nothing")
	}

	s, err := NewSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	// Non-vacuity: openable BEFORE the sweep. Without this the assertion below
	// would also pass for a value that was never openable at all.
	if err := v.Openable(); err != nil {
		t.Fatalf("Openable before the sweep = %v, want nil", err)
	}

	sweepForOpenableTest(t)

	// The value genuinely cannot be opened now; the sweep took the provider's
	// key.
	if _, err := v.Open(t.Context()); err == nil {
		t.Fatal("Open succeeded after the sweep; this provider's key was supposed to be swept, " +
			"so the fail-open this test guards cannot arise and the test proves nothing")
	}

	if err := v.Openable(); err == nil {
		t.Error("Openable returned nil for a value that cannot be opened: an external provider " +
			"that reports no health must not be assumed healthy; that is the " +
			"fail-open this change closes")
	} else if !errors.Is(err, ErrOpenabilityUnknown) {
		t.Errorf("Openable after the sweep = %v, want ErrOpenabilityUnknown: this package cannot "+
			"know whether the sweep took what this provider needed, and must say so rather "+
			"than guess either way", err)
	}
}

// TestSealedEnclave_OpenableBelievesAProviderThatReports pins that a
// HealthReporter answer is terminal: the sweep-generation fallback does not
// override it, so a provider can still report nil after a sweep.
func TestSealedEnclave_OpenableBelievesAProviderThatReports(t *testing.T) {
	t.Run("reportsHealthyAfterASweep", func(t *testing.T) {
		s, err := NewSealer(
			WithKeyProtector(healthyProtector{newMapKeyProtector(t)}),
		)
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		sweepForOpenableTest(t)

		if err := v.Openable(); err != nil {
			t.Errorf("Openable = %v, want nil: the provider reported healthy and its answer is "+
				"authoritative; the generation fallback must not second-guess it", err)
		}
		// And the report agrees with reality, which is what makes believing it
		// defensible rather than merely convenient.
		e, err := v.Open(t.Context())
		if err != nil {
			t.Fatalf("Open = %v, but the provider reported healthy; one of the two is wrong", err)
		}
		e.Destroy()
	})

	t.Run("reportsWipedAfterASweep", func(t *testing.T) {
		p := newEnclaveBackedProtector(t)
		s, err := NewSealer(
			WithKeyProtector(reportingProtector{p}),
		)
		if err != nil {
			t.Fatalf("NewSealer: %v", err)
		}
		v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		defer v.Destroy()

		if err := v.Openable(); err != nil {
			t.Fatalf("Openable before the sweep = %v, want nil", err)
		}

		sweepForOpenableTest(t)

		// The PRECISE answer, not the fallback: a provider that can tell the
		// difference reports ErrSealerWiped, and the caller learns what
		// actually happened instead of that we could not tell.
		if err := v.Openable(); !errors.Is(err, ErrSealerWiped) {
			t.Errorf("Openable = %v, want ErrSealerWiped: an opted-in provider that knows its key "+
				"was destroyed must report it, not fall back to ErrOpenabilityUnknown", err)
		}
		if errors.Is(v.Openable(), ErrOpenabilityUnknown) {
			t.Error("an opted-in provider's precise answer was replaced by the fallback")
		}
	})
}

// TestSealedEnclave_OpenableUnknownOnlyAfterASweep pins that
// ErrOpenabilityUnknown appears only after a sweep; before one, Openable
// returns nil.
func TestSealedEnclave_OpenableUnknownOnlyAfterASweep(t *testing.T) {
	p := newEnclaveBackedProtector(t)
	s, err := NewSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	// No sweep has run. The value demonstrably opens, so nil is the TRUE
	// answer and anything else is a false alarm on the common path.
	if err := v.Openable(); err != nil {
		t.Errorf("Openable with no sweep = %v, want nil: this value opens right now, and an "+
			"answer that never says so is not honesty", err)
	}
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("control: Open failed, so nil above was not the true answer: %v", err)
	}
	e.Destroy()

	sweepForOpenableTest(t)

	// Only now does it become unknown. The answer CHANGED, which is what makes
	// it a signal rather than a shrug.
	if err := v.Openable(); !errors.Is(err, ErrOpenabilityUnknown) {
		t.Errorf("Openable after the sweep = %v, want ErrOpenabilityUnknown", err)
	}
}

// TestSealedEnclave_OpenableGenerationDoesNotAffectModeRootKey pins that the
// fallback is scoped to the mode that needs it.
//
// In ModeRootKey the hierarchy is this package's own enclaves and it inspects
// them directly, so a nil there is KNOWLEDGE, not ignorance, and a sweep that
// provably did not take them must not downgrade it.
func TestSealedEnclave_OpenableGenerationDoesNotAffectModeRootKey(t *testing.T) {
	// Bump the generation before sealing so a value exists that was sealed
	// under an older generation than the current one — the precondition the
	// fallback triggers on — without wiping this sealer's own hierarchy.
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	// Two, not one: an even sequence means quiescent and a real sweep bumps
	// twice. An odd value would mark every later test's seals as overlapping a
	// sweep.
	sweepGen.Add(2) // a completed sweep elsewhere; this sealer's hierarchy is untouched

	if got := sweepGeneration(); got == v.sealedAtGen {
		t.Fatal("the generation did not advance, so this test's precondition does not hold")
	}
	if err := v.Openable(); err != nil {
		t.Errorf("Openable = %v, want nil: ModeRootKey's hierarchy is in-process and was "+
			"inspected directly, so its nil is knowledge and the generation fallback must "+
			"not override it", err)
	}
}

// TestWipeAll_BumpsTheGenerationBeforeDestroying pins WipeAll's order: bump
// the generation, then destroy. The reverse opens a window in which the keys
// are gone but the generation reads old, so Openable fails open. The test parks
// inside the window and observes it.
func TestWipeAll_BumpsTheGenerationBeforeDestroying(t *testing.T) {
	freshProcessSealer(t)

	e, err := NewMemoryEnclaveCopy([]byte("material that the sweep will destroy"))
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}

	before := sweepGeneration()

	var (
		mu           sync.Mutex
		genInWindow  uint64
		aliveInWndow bool
		parked       bool
	)

	swapSeam(t, &sweepParkedForTest, func() {
		mu.Lock()
		defer mu.Unlock()
		parked = true
		genInWindow = sweepGeneration()
		aliveInWndow = e.IsAlive()
	})

	if _, err := WipeAll(context.Background()); err != nil {
		t.Fatalf("WipeAll: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Instrument validation: a seam that never fired would make every
	// assertion below vacuously true.
	if !parked {
		t.Fatal("the park seam never ran, so this test observed nothing")
	}
	if !aliveInWndow {
		t.Fatal("the enclave was already destroyed when the seam ran, so the seam is not " +
			"inside the window it claims to be and proves nothing about the order")
	}
	if genInWindow != before+1 {
		t.Errorf("inside the window the generation is %d, want %d (before=%d): the bump must "+
			"happen BEFORE anything is destroyed, or a value sealed earlier reads as "+
			"openable while its keys are already gone", genInWindow, before+1, before)
	}
}

// TestWipeAll_GenerationIsMonotonicAcrossSweeps pins that the counter is not
// reset. A reset would let a value sealed later read as older than one sealed
// earlier, which is the single thing the comparison must never do.
func TestWipeAll_GenerationIsMonotonicAcrossSweeps(t *testing.T) {
	freshProcessSealer(t)

	seen := make([]uint64, 0, 3)
	for i := 0; i < 3; i++ {
		if _, err := WipeAll(context.Background()); err != nil {
			t.Fatalf("WipeAll %d: %v", i, err)
		}
		seen = append(seen, sweepGeneration())
		freshProcessSealer(t)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] <= seen[i-1] {
			t.Errorf("generation went %d -> %d; it must strictly increase", seen[i-1], seen[i])
		}
	}
}

// TestSealedEnclave_OpenableSuspectsASealThatOverlappedASweep pins that a
// seal made while WipeAll is between its bump and its destruction is reported
// as unknown. The odd sequence parity records the sweep in flight, which a
// plain count cannot.
func TestSealedEnclave_OpenableSuspectsASealThatOverlappedASweep(t *testing.T) {
	freshProcessSealer(t)

	p := newEnclaveBackedProtector(t)
	s, err := NewSealer(WithKeyProtector(p))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	var (
		mu               sync.Mutex
		v                *SealedEnclave
		sealErr          error
		parked           bool
		genAtSeal        uint64
		openableInWindow error
	)

	// Seal from INSIDE the sweep window, between the bump and the destruction.
	swapSeam(t, &sweepParkedForTest, func() {
		mu.Lock()
		defer mu.Unlock()
		parked = true
		genAtSeal = sweepGeneration()
		v, sealErr = s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))

		// Asked inside the window: the count still equals what the seal
		// recorded, so only the odd generation shows a sweep was underway.
		if sealErr == nil {
			openableInWindow = v.Openable()
		}
	})

	if _, err := WipeAll(context.Background()); err != nil {
		t.Fatalf("WipeAll: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if !parked {
		t.Fatal("the park seam never ran; this test observed nothing")
	}
	if sealErr != nil {
		t.Fatalf("the seal inside the sweep window failed (%v): nothing has been destroyed at that "+
			"point, so a seal there must succeed — and the race this pins needs one that does", sealErr)
	}
	defer v.Destroy()

	// Instrument validation: the seal really did happen mid-sweep.
	if !sweepInFlight(genAtSeal) {
		t.Fatalf("the generation at seal time was %d, which is not odd, so the seal did not "+
			"overlap a sweep and this test proves nothing", genAtSeal)
	}

	// The assertion the parity exists for: inside the window the count had not
	// moved, so anything reading the count alone said "fine".
	if !errors.Is(openableInWindow, ErrOpenabilityUnknown) {
		t.Errorf("Openable INSIDE the sweep window = %v, want ErrOpenabilityUnknown: the "+
			"sequence still read equal to the value's own, so only its odd parity records "+
			"that a sweep was in flight and about to take this provider's key",
			openableInWindow)
	}

	// And it still reports unknown once the sweep has completed, where the
	// changed count is what carries it.
	if got := v.Openable(); !errors.Is(got, ErrOpenabilityUnknown) {
		t.Errorf("Openable for a value sealed mid-sweep = %v, want ErrOpenabilityUnknown: the "+
			"sequence reads equal at both ends, and only its parity records that a sweep "+
			"was in flight when this was sealed", got)
	}
}

// TestSealer_ProviderHealthIsIgnoredInRootKeyMode pins that a RootUnsealer's
// HealthReporter is not consulted: the sealer's own hierarchy is alive and
// authoritative, and a provider report must not overrule it.
func TestSealer_ProviderHealthIsIgnoredInRootKeyMode(t *testing.T) {
	freshProcessSealer(t)

	called := false
	s, err := NewSealer(WithRootUnsealer(wipedReportingUnsealer{NewSoftwareProvider(), &called}))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	if err := v.Openable(); err != nil {
		t.Errorf("Openable = %v, want nil: this sealer's own hierarchy is alive and "+
			"authoritative, and HealthReporter is documented as ignored in ModeRootKey", err)
	}
	if called {
		t.Error("HealthReporter was consulted in ModeRootKey, which its documentation " +
			"says it is not")
	}

	// The control that makes the nil above meaningful: the value really opens.
	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open = %v; Openable said nil, so one of the two is wrong", err)
	}
	e.Destroy()
}

// TestWipeAll_ConcurrentSweepsKeepTheParityInvariant pins the single-writer
// requirement of the sweep sequence lock: whenever a sweep is inside its
// window, the sequence is odd. A second concurrent sweep would flip it back to
// even.
func TestWipeAll_ConcurrentSweepsKeepTheParityInvariant(t *testing.T) {
	freshProcessSealer(t)

	const sweepers = 8

	var (
		mu       sync.Mutex
		observed []uint64
	)
	swapSeam(t, &sweepParkedForTest, func() {
		g := sweepGeneration()
		mu.Lock()
		observed = append(observed, g)
		mu.Unlock()
		// Widen the window so a second sweep, if it were able to start, would
		// have every chance to land its own bump inside this one.
		runtime.Gosched()
	})

	var wg sync.WaitGroup
	for i := 0; i < sweepers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := WipeAll(context.Background()); err != nil {
				t.Errorf("WipeAll: %v", err)
			}
		}()
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()

	// Instrument validation: every sweep must have reached the window, or the
	// invariant below is asserted over fewer samples than it appears to be.
	if len(observed) != sweepers {
		t.Fatalf("the park seam fired %d times, want %d; this test did not observe what it "+
			"claims to", len(observed), sweepers)
	}
	for i, g := range observed {
		if !sweepInFlight(g) {
			t.Errorf("sweep %d observed sequence %d inside its own window, which is EVEN and "+
				"therefore reads as 'no sweep running'. Two sweeps overlapped and the "+
				"single-writer invariant the parity depends on is broken", i, g)
		}
	}
}

// openBudget is a budget generous enough for one open of sealedMaterial —
// destination plus the transient key page, with slack — expressed in pages so
// it is correct on any page size.
func openBudget(pages int64) int64 {
	return LockedSize(1) * pages
}

// sealForBudgetTest returns a sealed value under a private ModeRootKey sealer,
// so nothing here depends on (or disturbs) the process sealer.
func sealForBudgetTest(t *testing.T) *SealedEnclave {
	t.Helper()
	s, err := NewSealer()
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	t.Cleanup(func() { _ = v.Destroy() })
	return v
}

// TestSealedEnclave_OpenWithAdmitsTheDestination pins that OpenWith's result
// is reserved from the supplied Allocator. The assertion is on InUse: an
// OpenWith that ignored the Allocator would pass every correctness check.
func TestSealedEnclave_OpenWithAdmitsTheDestination(t *testing.T) {
	v := sealForBudgetTest(t)

	a, err := NewAllocator(openBudget(8))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if before := a.InUse(); before != 0 {
		t.Fatalf("a fresh Allocator reports %d bytes in use; this test attributes everything below to the open", before)
	}

	e, err := v.OpenWith(t.Context(), a)
	if err != nil {
		t.Fatalf("OpenWith: %v", err)
	}
	defer e.Destroy()

	// The material is right — an admitted open is still an open.
	if !holds(e, sealedMaterial) {
		t.Error("OpenWith returned the wrong material")
	}

	// Exactly the destination: zero would mean the unadmitted constructor was
	// used; more would mean a transient reservation was never returned.
	want := LockedSize(len(sealedMaterial))
	if got := a.InUse(); got != want {
		t.Errorf("after OpenWith the Allocator reports %d bytes in use, want %d "+
			"(the page-rounded destination, and nothing else still held)", got, want)
	}
}

// TestSealedEnclave_OpenWithReturnsTheReservationOnDestroy pins that
// destroying the result returns its reservation, so repeated opens do not leak
// budget.
func TestSealedEnclave_OpenWithReturnsTheReservationOnDestroy(t *testing.T) {
	v := sealForBudgetTest(t)

	a, err := NewAllocator(openBudget(8))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// Several sequential opens, each destroyed: a budget that leaked one
	// reservation per open would be exhausted well before the last of these.
	const rounds = 6
	for i := 0; i < rounds; i++ {
		e, err := v.OpenWith(t.Context(), a)
		if err != nil {
			t.Fatalf("OpenWith on round %d of %d: %v (a budget sized for one open cannot "+
				"serve the next unless Destroy returns the reservation)", i+1, rounds, err)
		}
		if !holds(e, sealedMaterial) {
			t.Fatalf("round %d returned the wrong material", i+1)
		}
		e.Destroy()

		if got := a.InUse(); got != 0 {
			t.Fatalf("after Destroy on round %d the Allocator still reports %d bytes in use, want 0", i+1, got)
		}
	}
}

// TestSealedEnclave_OpenWithRefusesANilAllocator pins that a nil Allocator
// is refused with ErrNilAllocator rather than treated as no budget.
func TestSealedEnclave_OpenWithRefusesANilAllocator(t *testing.T) {
	v := sealForBudgetTest(t)

	e, err := v.OpenWith(t.Context(), nil)
	if !errors.Is(err, ErrNilAllocator) {
		t.Errorf("OpenWith(nil) = %v, want ErrNilAllocator: a nil Allocator must not silently "+
			"fall back to an unadmitted allocation", err)
	}
	if e != nil {
		t.Error("OpenWith(nil) returned an enclave; it must allocate nothing")
		e.Destroy()
	}

	// The refusal is about the ARGUMENT and does not depend on the value's
	// state, so a destroyed value reports the same thing. Otherwise the error
	// a caller sees for a lost allocator would depend on lifecycle timing.
	d := sealForBudgetTest(t)
	d.Destroy()
	if _, err := d.OpenWith(t.Context(), nil); !errors.Is(err, ErrNilAllocator) {
		t.Errorf("OpenWith(nil) on a destroyed value = %v, want ErrNilAllocator", err)
	}

	// A nil RECEIVER is a different mistake and keeps its own answer.
	var nilValue *SealedEnclave
	if _, err := nilValue.OpenWith(t.Context(), nil); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("(*SealedEnclave)(nil).OpenWith(t.Context(), nil) = %v, want ErrEnclaveDestroyed", err)
	}

	// And Open — the unbudgeted path — is unaffected: it has nothing to
	// refuse, so it never reports this error.
	o, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open after a refused OpenWith: %v", err)
	}
	o.Destroy()
}

// TestSealedEnclave_OpenAllocatesOutsideAnyBudget pins that Open allocates
// unadmitted, as documented, for callers that do not budget.
func TestSealedEnclave_OpenAllocatesOutsideAnyBudget(t *testing.T) {
	v := sealForBudgetTest(t)

	a, err := NewAllocator(openBudget(8))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer e.Destroy()

	if got := a.InUse(); got != 0 {
		t.Errorf("an unrelated Allocator reports %d bytes in use after a plain Open, want 0", got)
	}
}

// TestSealedEnclave_OpenWithRefusesWhatTheBudgetCannotCover pins the refusal
// path and, more importantly, what a refusal COSTS: nothing. The sealed value
// survives a budget refusal intact and opens afterwards, so a tight budget is
// backpressure rather than a lost credential.
func TestSealedEnclave_OpenWithRefusesWhatTheBudgetCannotCover(t *testing.T) {
	v := sealForBudgetTest(t)

	// A sub-page budget constructs but admits nothing, reaching the refusal
	// without depending on the page size.
	a, err := NewAllocator(1)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := v.OpenWith(t.Context(), a)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("OpenWith under a sub-page budget = %v, want ErrBudgetExhausted", err)
	}
	if e != nil {
		t.Error("a refused OpenWith returned an enclave")
		e.Destroy()
	}

	// A BudgetError carries the figures, and they must be the page-rounded
	// ones the kernel charges rather than the sizes asked for.
	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("the refusal is not a *BudgetError: %v", err)
	}
	if be.Limit != 1 {
		t.Errorf("BudgetError.Limit = %d, want 1", be.Limit)
	}
	if be.Requested != LockedSize(len(sealedMaterial)) {
		t.Errorf("BudgetError.Requested = %d, want %d: the figures are the page-rounded ones the "+
			"kernel charges, not the size asked for", be.Requested, LockedSize(len(sealedMaterial)))
	}

	// Nothing was left reserved by the refusal.
	if got := a.InUse(); got != 0 {
		t.Errorf("a refused OpenWith left %d bytes reserved, want 0", got)
	}

	// The value is untouched: the refusal was about the budget, not about it.
	o, err := v.Open(t.Context())
	if err != nil {
		t.Fatalf("Open after a budget refusal: %v (a refusal must not consume the value)", err)
	}
	if !holds(o, sealedMaterial) {
		t.Error("the material changed across a budget refusal")
	}
	o.Destroy()

	// And a budget that CAN cover the open admits it, so the refusal above was
	// the budget's doing and not a value that never opened.
	roomy, err := NewAllocator(openBudget(4))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e2, err := v.OpenWith(t.Context(), roomy)
	if err != nil {
		t.Fatalf("OpenWith under a four-page budget: %v", err)
	}
	e2.Destroy()
}

// TestSealedEnclave_OpenWithGatesOnTheDestination pins that the destination
// is reserved before any other work, so a refused open allocates no locked
// memory and touches no key. The instrument is the provider's Unprotect count:
// the DEK is allocated immediately before Unprotect, so zero calls means the
// refusal came first.
func TestSealedEnclave_OpenWithGatesOnTheDestination(t *testing.T) {
	kp := newMapKeyProtector(t)
	s, err := NewSealer(WithKeyProtector(kp))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	// Three pages of material, so a one-page budget cannot cover the
	// destination and the refusal is unambiguous.
	page := LockedSize(1)
	material := bytes.Repeat([]byte{0x5B}, int(3*page))
	v, err := s.Seal(t.Context(), append([]byte(nil), material...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	tooSmall, err := NewAllocator(page)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	beforeUnprotects, beforeLedger := kp.unprotectCount(), liveCount()

	e, err := v.OpenWith(t.Context(), tooSmall)
	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("OpenWith under a one-page budget = %v, want a *BudgetError", err)
	}
	if e != nil {
		e.Destroy()
	}

	// The refusal named the DESTINATION, so that is what was reserved first.
	if be.Requested != LockedSize(len(material)) {
		t.Errorf("the refused reservation asked for %d bytes, want %d (the destination). "+
			"A key-page figure here would mean something was reserved ahead of the gate",
			be.Requested, LockedSize(len(material)))
	}
	// And nothing beyond the gate ran.
	if got := kp.unprotectCount() - beforeUnprotects; got != 0 {
		t.Errorf("a budget-refused open called Unprotect %d time(s), want 0: the DEK is allocated "+
			"immediately before that call, so this means a locked page was taken before the budget "+
			"was consulted", got)
	}
	if got := liveCount(); got != beforeLedger {
		t.Errorf("a budget-refused open left the ledger at %d, was %d: it allocated locked memory "+
			"it should never have reached", got, beforeLedger)
	}

	// Non-vacuity, and the single-reservation property in one number: a budget
	// of EXACTLY the destination admits the open. Charging the DEK as a second
	// reservation would refuse this, so the two halves of this test also pin
	// that an open costs the budget one reservation and not two.
	exact, err := NewAllocator(LockedSize(len(material)))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	admitted, err := v.OpenWith(t.Context(), exact)
	if err != nil {
		t.Fatalf("OpenWith under a budget of exactly one destination = %v, want success: an open "+
			"takes ONE reservation, so this is the smallest budget that serves it", err)
	}
	if !holds(admitted, material) {
		t.Error("the admitted open returned the wrong material")
	}
	if got, want := exact.InUse(), LockedSize(len(material)); got != want {
		t.Errorf("the admitted open holds %d bytes, want %d", got, want)
	}
	if got := kp.unprotectCount() - beforeUnprotects; got != 1 {
		t.Errorf("the admitted open called Unprotect %d time(s), want 1; the refused one above "+
			"contributed none, which is what makes its zero meaningful", got)
	}
	admitted.Destroy()
}

// TestSealedEnclave_OpenWithConcurrentCallersDoNotStarveEachOther pins that
// goroutines sharing a budget sized for one open let exactly one succeed.
// Charging the transient key page as a second reservation would let callers
// fragment the budget so none succeeds.
func TestSealedEnclave_OpenWithConcurrentCallersDoNotStarveEachOther(t *testing.T) {
	v := sealForBudgetTest(t)

	// Exactly one destination: every open but one must be refused, and one
	// must succeed.
	a, err := NewAllocator(LockedSize(len(sealedMaterial)))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	const rounds, goroutines = 20, 8
	for round := 0; round < rounds; round++ {
		var wg sync.WaitGroup
		opened := make(chan *MemoryEnclave, goroutines)
		refused := make(chan error, goroutines)
		start := make(chan struct{})

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				e, err := v.OpenWith(t.Context(), a)
				if err != nil {
					refused <- err
					return
				}
				opened <- e
			}()
		}
		close(start)
		wg.Wait()
		close(opened)
		close(refused)

		wins := 0
		for e := range opened {
			wins++
			if !holds(e, sealedMaterial) {
				t.Fatal("a concurrent open returned the wrong material")
			}
			e.Destroy()
		}
		for err := range refused {
			if !errors.Is(err, ErrBudgetExhausted) {
				t.Fatalf("a refused open reported %v, want ErrBudgetExhausted", err)
			}
		}
		if wins == 0 {
			t.Fatalf("round %d: all %d concurrent opens were refused under a budget sized for one. "+
				"That is the fragmentation failure a second reservation per open causes: callers "+
				"take a transient page each and then none of them can afford a destination", round, goroutines)
		}
		if got := a.InUse(); got != 0 {
			t.Fatalf("round %d left %d bytes reserved, want 0", round, got)
		}
	}
}

// TestSealedEnclave_OpenWithOnARetiredGeneration covers the open path with the
// most locked memory in flight: a value sealed under a retired KEK generation
// materializes that generation's key for a single unwrap, on top of the DEK.
//
// Both are transient and neither is charged, so the budget the caller needs is
// still one destination — which is the claim being pinned. What the caller
// gives up for that is stated on OpenWith: the process peak exceeds the budget
// by up to two pages while this open is in flight.
func TestSealedEnclave_OpenWithOnARetiredGeneration(t *testing.T) {
	short := []byte("short-credential")

	s, err := NewSealer() // software provider, ModeRootKey
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), short...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	s.mu.RLock()
	genBefore := s.kekGen
	s.mu.RUnlock()

	// Force the rotation, exactly as TestSealer_KEKRotatesAtTheMessageLimit
	// does: park the counter at the bound and seal past it.
	s.kekUsed.Store(kekMessageLimit)
	throwaway, err := s.Seal(t.Context(), append([]byte(nil), short...))
	if err != nil {
		t.Fatalf("Seal past the message limit: %v", err)
	}
	defer throwaway.Destroy()

	s.mu.RLock()
	genAfter := s.kekGen
	s.mu.RUnlock()
	if genAfter == genBefore {
		t.Fatalf("the KEK did not rotate (generation still %d); this test needs a retired "+
			"generation to exercise the unwrap path", genBefore)
	}

	// One destination, and that is all it takes — rotation must never strand a
	// value, and it must not silently raise what a caller has to budget either.
	a, err := NewAllocator(LockedSize(len(short)))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := v.OpenWith(t.Context(), a)
	if err != nil {
		t.Fatalf("OpenWith on a retired-generation value under a one-destination budget: %v", err)
	}
	if !holds(e, short) {
		t.Error("the retired-generation value opened to the wrong material")
	}
	if got, want := a.InUse(), LockedSize(len(short)); got != want {
		t.Errorf("after the open the Allocator holds %d bytes, want %d", got, want)
	}
	e.Destroy()
	if got := a.InUse(); got != 0 {
		t.Errorf("after Destroy the Allocator holds %d bytes, want 0", got)
	}
}

// TestSealedEnclave_OpenWithIsConcurrencySafe runs admitted opens from many
// goroutines against one budget: under -race it checks the open path, and the
// budget returns to zero afterwards.
func TestSealedEnclave_OpenWithIsConcurrencySafe(t *testing.T) {
	v := sealForBudgetTest(t)

	const goroutines = 16
	a, err := NewAllocator(openBudget(int64(goroutines) * 4))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e, err := v.OpenWith(t.Context(), a)
			if err != nil {
				errs <- err
				return
			}
			if !holds(e, sealedMaterial) {
				errs <- errors.New("concurrent OpenWith returned the wrong material")
			}
			e.Destroy()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	if got := a.InUse(); got != 0 {
		t.Errorf("after %d concurrent opens and destroys the Allocator holds %d bytes, want 0", goroutines, got)
	}
}

// TestSealedEnclave_OpenWithOnADestroyedValue keeps the lifecycle answer the
// same on both entry points: a destroyed value is destroyed whichever way it
// is opened, and the refusal costs the budget nothing.
func TestSealedEnclave_OpenWithOnADestroyedValue(t *testing.T) {
	v := sealForBudgetTest(t)
	v.Destroy()

	a, err := NewAllocator(openBudget(8))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if _, err := v.OpenWith(t.Context(), a); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("OpenWith on a destroyed value = %v, want ErrEnclaveDestroyed", err)
	}
	if got := a.InUse(); got != 0 {
		t.Errorf("a refused OpenWith reserved %d bytes, want 0", got)
	}

	var nilValue *SealedEnclave
	if _, err := nilValue.OpenWith(t.Context(), a); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("(*SealedEnclave)(nil).OpenWith = %v, want ErrEnclaveDestroyed", err)
	}
}

// TestSealedEnclave_OpenWithPerOperationMode pins that the budget reaches the
// other mode too. ModePerOperation's unprotect allocates nothing itself, so
// what this proves is that the DEK and the destination are still admitted when
// a device — not an in-process hierarchy — supplies the key.
func TestSealedEnclave_OpenWithPerOperationMode(t *testing.T) {
	s, err := NewSealer(WithKeyProtector(newMapKeyProtector(t)))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	v, err := s.Seal(t.Context(), append([]byte(nil), sealedMaterial...))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	defer v.Destroy()

	a, err := NewAllocator(openBudget(8))
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := v.OpenWith(t.Context(), a)
	if err != nil {
		t.Fatalf("OpenWith in ModePerOperation: %v", err)
	}
	if !holds(e, sealedMaterial) {
		t.Error("opened to the wrong material")
	}
	if got, want := a.InUse(), LockedSize(len(sealedMaterial)); got != want {
		t.Errorf("after OpenWith the Allocator holds %d bytes, want %d", got, want)
	}
	e.Destroy()
	if got := a.InUse(); got != 0 {
		t.Errorf("after Destroy the Allocator holds %d bytes, want 0", got)
	}
}

// TestSealedEnclave_NoForeignBytesConstructor pins that no exported API turns
// caller-supplied bytes into an openable *SealedEnclave besides the plaintext
// constructors. The envelope format is internal, unversioned and keyed to a
// process-lifetime Sealer; an unmarshaller would make it accidentally
// permanent. If persistence is ever designed, amend this test as part of that
// design.
func TestSealedEnclave_NoForeignBytesConstructor(t *testing.T) {
	// The sanctioned constructors: both take PLAINTEXT and produce a sealed
	// value, which is the direction the contract permits. Nothing else may
	// combine bytes-in with *SealedEnclave-out.
	allowed := map[string]bool{
		"NewSealed": true, // package-level, process sealer
		"Seal":      true, // (*Sealer), explicit sealer
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}

	fset := token.NewFileSet()
	checkedFiles, flagged := 0, 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		checkedFiles++

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}

			// Decoder-shaped methods on the sealed types are refused BY NAME,
			// whatever their signature: these are the interfaces (encoding,
			// gob, json) through which foreign bytes arrive implicitly, where
			// no reviewer sees a call site at all.
			if recv := receiverTypeName(fn); recv == "SealedEnclave" || recv == "Sealer" {
				switch fn.Name.Name {
				case "UnmarshalBinary", "UnmarshalText", "UnmarshalJSON", "GobDecode", "DecodeMsgpack", "UnmarshalCBOR":
					flagged++
					t.Errorf("%s: %s.%s is a decoder for foreign bytes; see this test's rationale — "+
						"there is no persistence contract to decode against", name, recv, fn.Name.Name)
				}
			}

			if !returnsSealedEnclave(fn) || !takesForeignBytes(fn) {
				continue
			}
			if allowed[fn.Name.Name] {
				continue
			}
			flagged++
			t.Errorf("%s: exported %s takes caller bytes and returns a *SealedEnclave. "+
				"If those bytes are PLAINTEXT, add it to this test's allowlist with a comment. "+
				"If they are SEALED bytes, stop: sealed values have no persistence contract — no "+
				"stable format, no versioning, keys that die with the process — and this "+
				"constructor would make the internal format accidentally permanent. Design "+
				"persistence as a requirement (versioning, migration, provider signing for "+
				"transported envelopes) before adding any such entry point.", name, fn.Name.Name)
		}
	}

	// Vacuity guards: the walk must have seen the package and the allowlist
	// must describe reality — a renamed constructor would otherwise leave an
	// allowlist entry matching nothing and the guard checking nothing.
	if checkedFiles == 0 {
		t.Fatal("the guard parsed no files; it is checking nothing")
	}
	if flagged == 0 {
		for name := range allowed {
			if !functionExists(t, fset, name) {
				t.Errorf("allowlist names %q but no such function exists; update the allowlist with the rename", name)
			}
		}
	}
}

// receiverTypeName returns the bare type name of a method receiver, or "".
func receiverTypeName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	expr := fn.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// returnsSealedEnclave reports whether any result is *SealedEnclave or
// SealedEnclave.
func returnsSealedEnclave(fn *ast.FuncDecl) bool {
	if fn.Type.Results == nil {
		return false
	}
	for _, res := range fn.Type.Results.List {
		expr := res.Type
		if star, ok := expr.(*ast.StarExpr); ok {
			expr = star.X
		}
		if ident, ok := expr.(*ast.Ident); ok && ident.Name == "SealedEnclave" {
			return true
		}
	}
	return false
}

// takesForeignBytes reports whether any parameter is a []byte, a string, or
// an io.Reader — the shapes through which caller-supplied bytes arrive.
func takesForeignBytes(fn *ast.FuncDecl) bool {
	for _, param := range fn.Type.Params.List {
		switch typ := param.Type.(type) {
		case *ast.ArrayType:
			if typ.Len == nil {
				if ident, ok := typ.Elt.(*ast.Ident); ok && ident.Name == "byte" {
					return true
				}
			}
		case *ast.Ident:
			if typ.Name == "string" {
				return true
			}
		case *ast.SelectorExpr:
			if pkg, ok := typ.X.(*ast.Ident); ok && pkg.Name == "io" && typ.Sel.Name == "Reader" {
				return true
			}
		}
	}
	return false
}

// functionExists reports whether an exported function or method of that name
// is declared in any non-test file of the package.
func functionExists(t *testing.T, fset *token.FileSet, name string) bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading package directory: %v", err)
	}
	for _, entry := range entries {
		fname := entry.Name()
		if !strings.HasSuffix(fname, ".go") || strings.HasSuffix(fname, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", fname), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", fname, err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
				return true
			}
		}
	}
	return false
}

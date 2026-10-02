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

// Covers enclave.go: where a MemoryEnclave's material is in the process while
// it lives, and that it is nowhere after Destroy — measured by sweeping every
// readable mapping of the process (procfs_test.go), never by asking the
// library.
//
// Each sweep is paired with a CONTROL that proves it can see what it claims is
// absent: the material is found exactly where it is known to be before it is
// required to be gone. A sweep that found nothing in the first place would
// pass the absence check for free.

// TestEnclaveMaterialLivesOnlyInItsEnclaveAndIsGoneAfterDestroy follows one
// secret through every MemoryEnclave constructor a consumer has.
func TestEnclaveMaterialLivesOnlyInItsEnclaveAndIsGoneAfterDestroy(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		alloc, err := enclave.NewAllocator(16 * enclave.LockedSize(1))
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}

		// Generated straight into locked pages: the material never exists
		// anywhere but the enclave, from the first byte to the last.
		t.Run("NewMemoryEnclaveSized", func(t *testing.T) {
			n := newNeedle(t)
			e := enclaveFromNeedle(t, n)
			if err := e.Freeze(); err != nil {
				t.Fatalf("Freeze: %v", err)
			}
			hits, scanned := sweep(t, n)
			requireHitsExactly(t, "live, generated in place", hits, scanned, dataAddr(t, e))
			destroyAndRequireGone(t, e, n)
		})

		// The ownership contract: the constructor WIPES the caller's slice, so
		// the heap copy the material arrived in does not outlive it. The heap
		// copy is also the sweep's control for the Go heap: it must be found
		// there before the constructor runs.
		t.Run("NewMemoryEnclave", func(t *testing.T) {
			n := newNeedle(t)
			src := heapBytes(needleLen)
			n.fill(src)
			hits, scanned := sweep(t, n)
			requireHitsExactly(t, "caller's heap slice, before the constructor", hits, scanned, addrOfSlice(src))

			e, err := enclave.NewMemoryEnclave(src)
			if err != nil {
				t.Fatalf("NewMemoryEnclave: %v", err)
			}
			if !allZero(src) {
				t.Fatalf("NewMemoryEnclave did not wipe the caller's slice")
			}
			hits, scanned = sweep(t, n)
			requireHitsExactly(t, "live, after the constructor took ownership", hits, scanned, dataAddr(t, e))
			destroyAndRequireGone(t, e, n)
		})

		// The DOCUMENTED cost of the copying constructor: the source survives
		// on the heap until its owner wipes it, and the enclave's Destroy does
		// not (cannot) reach it.
		t.Run("NewMemoryEnclaveCopy", func(t *testing.T) {
			n := newNeedle(t)
			src := heapBytes(needleLen)
			n.fill(src)
			e, err := enclave.NewMemoryEnclaveCopy(src)
			if err != nil {
				t.Fatalf("NewMemoryEnclaveCopy: %v", err)
			}
			hits, scanned := sweep(t, n)
			requireHitsExactly(t, "live, copy constructor (source intact by contract)", hits, scanned, addrOfSlice(src), dataAddr(t, e))
			if err := e.Destroy(); err != nil {
				t.Fatalf("Destroy: %v", err)
			}
			hits, scanned = sweep(t, n)
			requireHitsExactly(t, "after Destroy, the caller's source remains", hits, scanned, addrOfSlice(src))
			enclave.Wipe(src)
			hits, scanned = sweep(t, n)
			requireHitsExactly(t, "after the caller wiped its source", hits, scanned)
		})

		t.Run("Allocator.New", func(t *testing.T) {
			n := newNeedle(t)
			src := heapBytes(needleLen)
			n.fill(src)
			e, err := alloc.New(src)
			if err != nil {
				t.Fatalf("Allocator.New: %v", err)
			}
			if !allZero(src) {
				t.Fatalf("Allocator.New did not wipe the caller's slice")
			}
			hits, scanned := sweep(t, n)
			requireHitsExactly(t, "live, admitted", hits, scanned, dataAddr(t, e))
			destroyAndRequireGone(t, e, n)
			if alloc.InUse() != 0 {
				t.Fatalf("Allocator.InUse = %d after Destroy, want 0", alloc.InUse())
			}
		})

		// A sized enclave left writable for its whole life (never frozen) is
		// wiped and released all the same.
		t.Run("Allocator.NewSized unfrozen", func(t *testing.T) {
			n := newNeedle(t)
			e, err := alloc.NewSized(needleLen)
			if err != nil {
				t.Fatalf("Allocator.NewSized: %v", err)
			}
			if err := e.WithBytes(func(b []byte) error { n.fill(b); return nil }); err != nil {
				t.Fatalf("filling: %v", err)
			}
			hits, scanned := sweep(t, n)
			requireHitsExactly(t, "live, unfrozen", hits, scanned, dataAddr(t, e))
			destroyAndRequireGone(t, e, n)
		})

		if n, err := enclave.WipeAll(context.Background()); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// TestDestroyedEnclaveRefusesEveryAccess checks the consumer-visible contract
// after Destroy: every accessor reports ErrEnclaveDestroyed (or false), and
// Destroy itself is idempotent.
func TestDestroyedEnclaveRefusesEveryAccess(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		n := newNeedle(t)
		e := enclaveFromNeedle(t, n)
		if !e.IsAlive() || e.Size() != needleLen {
			t.Fatalf("live enclave: IsAlive %t, Size %d", e.IsAlive(), e.Size())
		}
		var matched bool
		if err := e.WithBytes(func(b []byte) error { matched = n.equals(b); return nil }); err != nil || !matched {
			t.Fatalf("WithBytes on a live enclave: matched %t, err %v", matched, err)
		}
		if err := e.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if err := e.Destroy(); err != nil {
			t.Fatalf("second Destroy: %v, want nil (idempotent)", err)
		}
		if e.IsAlive() {
			t.Errorf("IsAlive after Destroy")
		}
		called := false
		if err := e.WithBytes(func([]byte) error { called = true; return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) || called {
			t.Errorf("WithBytes after Destroy: err %v, callback ran %t; want ErrEnclaveDestroyed and no call", err, called)
		}
		if _, err := e.Open(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Open after Destroy: err %v, want ErrEnclaveDestroyed", err)
		}
		if err := e.Freeze(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Freeze after Destroy: err %v, want ErrEnclaveDestroyed", err)
		}
		if ok, err := e.EqualToErr([]byte{0}); ok || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("EqualToErr after Destroy: (%t, %v), want (false, ErrEnclaveDestroyed)", ok, err)
		}
		if n, err := enclave.WipeAll(context.Background()); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// destroyAndRequireGone destroys e and requires the material to be absent
// from every readable mapping of the process afterwards.
func destroyAndRequireGone(t *testing.T, e *enclave.MemoryEnclave, n needle) {
	t.Helper()
	if err := e.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if e.IsAlive() {
		t.Fatalf("IsAlive after Destroy")
	}
	hits, scanned := sweep(t, n)
	requireHitsExactly(t, "after Destroy", hits, scanned)
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// TestEnclaveAccessorsTellTheTruth exercises the accessors a consumer reads an
// enclave through, against real locked memory: every constructor, the
// comparisons, the redacted String, the heap-copy accessors, and what each
// reports once the enclave is destroyed.
func TestEnclaveAccessorsTellTheTruth(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		const secret = "accessor material, 32 bytes long"

		fromString, err := enclave.NewMemoryEnclaveFromString(secret)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveFromString: %v", err)
		}
		src := []byte(secret)
		copied, err := enclave.NewMemoryEnclaveCopy(src)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveCopy: %v", err)
		}
		if string(src) != secret {
			t.Fatal("NewMemoryEnclaveCopy changed its source; it must leave the caller's buffer as it found it")
		}

		for name, e := range map[string]*enclave.MemoryEnclave{"FromString": fromString, "Copy": copied} {
			if e.Size() != len(secret) {
				t.Errorf("%s: Size = %d, want %d", name, e.Size(), len(secret))
			}
			if !e.EqualTo([]byte(secret)) || e.EqualTo([]byte(strings.ToUpper(secret))) {
				t.Errorf("%s: EqualTo does not compare by content", name)
			}
			if ok, err := e.EqualToErr([]byte(secret)); !ok || err != nil {
				t.Errorf("%s: EqualToErr = (%t, %v), want (true, nil)", name, ok, err)
			}
			if ok, err := e.EqualToErr([]byte("short")); ok || err != nil {
				t.Errorf("%s: EqualToErr(different length) = (%t, %v), want (false, nil)", name, ok, err)
			}
			if s := e.String(); strings.Contains(s, secret) || strings.Contains(s, secret[:8]) {
				t.Errorf("%s: String() leaks the material: %q", name, s)
			}
			// Open is the documented UNSAFE view: it aliases the enclave's own
			// read-only pages (a write would fault), so it is read and dropped,
			// never written. OpenString is the deliberate heap copy for legacy
			// string APIs.
			b, err := e.Open()
			if err != nil || string(b) != secret {
				t.Errorf("%s: Open = (%d bytes, %v)", name, len(b), err)
			}
			if s, err := e.OpenString(); err != nil || s != secret {
				t.Errorf("%s: OpenString = (%q, %v)", name, s, err)
			}
			if err := e.Destroy(); err != nil {
				t.Fatalf("%s: Destroy: %v", name, err)
			}
			if e.IsAlive() {
				t.Errorf("%s: alive after Destroy", name)
			}
			if _, err := e.EqualToErr([]byte(secret)); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
				t.Errorf("%s: EqualToErr after Destroy = %v, want ErrEnclaveDestroyed", name, err)
			}
			if e.EqualTo([]byte(secret)) {
				t.Errorf("%s: EqualTo after Destroy reported a match", name)
			}
			if _, err := e.Open(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
				t.Errorf("%s: Open after Destroy = %v, want ErrEnclaveDestroyed", name, err)
			}
			if _, err := e.OpenString(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
				t.Errorf("%s: OpenString after Destroy = %v, want ErrEnclaveDestroyed", name, err)
			}
			if s := e.String(); !strings.Contains(strings.ToLower(s), "destroyed") {
				t.Errorf("%s: String() after Destroy = %q, want it to say so", name, s)
			}
		}

		// Empty material is refused by every constructor, before any locked
		// memory is requested.
		if _, err := enclave.NewMemoryEnclaveFromString(""); !errors.Is(err, enclave.ErrEmptyEnclave) {
			t.Errorf("NewMemoryEnclaveFromString(\"\") = %v, want ErrEmptyEnclave", err)
		}
		if _, err := enclave.NewMemoryEnclaveCopy(nil); !errors.Is(err, enclave.ErrEmptyEnclave) {
			t.Errorf("NewMemoryEnclaveCopy(nil) = %v, want ErrEmptyEnclave", err)
		}
		if _, err := enclave.NewMemoryEnclaveSized(0); !errors.Is(err, enclave.ErrInvalidSize) {
			t.Errorf("NewMemoryEnclaveSized(0) = %v, want ErrInvalidSize", err)
		}

		if n, err := enclave.WipeAll(context.Background()); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// TestKeyScheduleErasureReportsThisBuild: the devcontainer builds without
// GOEXPERIMENT=runtimesecret, so this build does NOT erase key schedules and
// must say so — a deployment's startup check would otherwise trust an erasure
// that is not happening. The erasing build is proven by make
// test-runtimesecret.
func TestKeyScheduleErasureReportsThisBuild(t *testing.T) {
	if enclave.KeyScheduleErasure() {
		t.Fatal("KeyScheduleErasure() = true in a build without GOEXPERIMENT=runtimesecret")
	}
}

// TestEnclaveErrorTypesRenderEveryValue: the release and allocation error
// types are exported, so a caller can build any value of them — including the
// zero value — and each must still render in the package's voice and unwrap
// to nothing it does not carry.
func TestEnclaveErrorTypesRenderEveryValue(t *testing.T) {
	for _, e := range []error{&enclave.UnwipedReleaseError{}, &enclave.LockedMemoryError{}} {
		if msg := e.Error(); !strings.HasPrefix(msg, "enclave: ") {
			t.Errorf("%T{}.Error() = %q, want a message in the package's voice", e, msg)
		}
	}
	if errors.Unwrap(&enclave.LockedMemoryError{}) != nil {
		t.Error("a LockedMemoryError with no cause unwraps to something")
	}
}

// TestDestroyedAndNilEnclavesAnswerSafely covers what every accessor of a
// destroyed — or nil — MemoryEnclave reports: each answers with the
// documented sentinel or zero value and never touches unmapped memory.
func TestDestroyedAndNilEnclavesAnswerSafely(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		var nilEnclave *enclave.MemoryEnclave
		if nilEnclave.Size() != 0 || nilEnclave.IsAlive() || nilEnclave.Destroy() != nil {
			t.Error("a nil *MemoryEnclave does not answer as an empty, dead, already-released enclave")
		}
		if err := nilEnclave.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("WithBytes on a nil *MemoryEnclave = %v, want ErrEnclaveDestroyed", err)
		}
		if b, err := nilEnclave.Open(); b != nil || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Open on a nil *MemoryEnclave = (%v, %v), want (nil, ErrEnclaveDestroyed)", b, err)
		}
		if err := nilEnclave.Freeze(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Freeze on a nil *MemoryEnclave = %v, want ErrEnclaveDestroyed", err)
		}

		e, err := enclave.NewMemoryEnclaveSized(32)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
		}
		if err := e.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if e.Size() != 0 {
			t.Errorf("Size of a destroyed enclave = %d, want 0", e.Size())
		}
		if err := e.Destroy(); err != nil {
			t.Errorf("a second Destroy = %v, want nil (idempotent)", err)
		}
		if err := e.Freeze(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Freeze of a destroyed enclave = %v, want ErrEnclaveDestroyed", err)
		}
		if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("WithBytes of a destroyed enclave = %v, want ErrEnclaveDestroyed", err)
		}
	})
}

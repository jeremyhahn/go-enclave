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
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// Where a memory enclave's material lives, and that it is gone after Destroy,
// measured by sweeping every readable mapping (procfs_test.go). Each absence
// check is preceded by a control that finds the material where it is known to
// be, so a blind sweep cannot pass.

// TestMemoryEnclave_EnclaveMaterialLivesOnlyInItsEnclaveAndIsGoneAfterDestroy follows one
// secret through every memory enclave constructor a consumer has.
func TestMemoryEnclave_EnclaveMaterialLivesOnlyInItsEnclaveAndIsGoneAfterDestroy(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		alloc, err := enclave.NewAllocator(16 * enclave.LockedSize(1))
		if err != nil {
			t.Fatalf("NewAllocator: %v", err)
		}

		// Generated straight into locked pages: never anywhere but the enclave.
		t.Run("NewMemorySized", func(t *testing.T) {
			n := newNeedle(t)
			e := enclaveFromNeedle(t, n)
			if err := e.(enclave.Freezer).Freeze(); err != nil {
				t.Fatalf("Freeze: %v", err)
			}
			hits, scanned := sweep(t, n)
			requireHitsExactly(t, "live, generated in place", hits, scanned, dataAddr(t, e))
			destroyAndRequireGone(t, e, n)
		})

		// The constructor wipes the caller's slice. The heap copy is also the
		// sweep's control: it must be found before the constructor runs.
		t.Run("NewMemory", func(t *testing.T) {
			n := newNeedle(t)
			src := heapBytes(needleLen)
			n.fill(src)
			hits, scanned := sweep(t, n)
			requireHitsExactly(t, "caller's heap slice, before the constructor", hits, scanned, addrOfSlice(src))

			e, err := enclave.NewMemory(src)
			if err != nil {
				t.Fatalf("NewMemory: %v", err)
			}
			if !memscan.AllZero(src) {
				t.Fatalf("NewMemory did not wipe the caller's slice")
			}
			hits, scanned = sweep(t, n)
			requireHitsExactly(t, "live, after the constructor took ownership", hits, scanned, dataAddr(t, e))
			destroyAndRequireGone(t, e, n)
		})

		// The copying constructor's documented cost: the source survives on
		// the heap until its owner wipes it; Destroy cannot reach it.
		t.Run("NewMemoryCopy", func(t *testing.T) {
			n := newNeedle(t)
			src := heapBytes(needleLen)
			n.fill(src)
			e, err := enclave.NewMemoryCopy(src)
			if err != nil {
				t.Fatalf("NewMemoryCopy: %v", err)
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
			if !memscan.AllZero(src) {
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

// TestMemoryEnclave_DestroyedEnclaveRefusesEveryAccess checks the consumer-visible contract
// after Destroy: every accessor reports ErrEnclaveDestroyed (or false), and
// Destroy itself is idempotent.
func TestMemoryEnclave_DestroyedEnclaveRefusesEveryAccess(t *testing.T) {
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
		if err := e.(enclave.Freezer).Freeze(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Freeze after Destroy: err %v, want ErrEnclaveDestroyed", err)
		}
		if ok, err := e.EqualTo([]byte{0}); ok || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("EqualTo after Destroy: (%t, %v), want (false, ErrEnclaveDestroyed)", ok, err)
		}
		if n, err := enclave.WipeAll(context.Background()); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// destroyAndRequireGone destroys e and requires the material to be absent
// from every readable mapping of the process afterwards.
func destroyAndRequireGone(t *testing.T, e enclave.ByteAccess, n needle) {
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

// TestMemoryEnclave_EnclaveAccessorsTellTheTruth exercises the accessors a consumer reads an
// enclave through, against real locked memory: every constructor, the
// comparisons, the redacted String, the scoped borrow, and what each
// reports once the enclave is destroyed.
func TestMemoryEnclave_EnclaveAccessorsTellTheTruth(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		const secret = "accessor material, 32 bytes long"

		moved, err := enclave.NewMemory([]byte(secret))
		if err != nil {
			t.Fatalf("NewMemory: %v", err)
		}
		src := []byte(secret)
		copied, err := enclave.NewMemoryCopy(src)
		if err != nil {
			t.Fatalf("NewMemoryCopy: %v", err)
		}
		if string(src) != secret {
			t.Fatal("NewMemoryCopy changed its source; it must leave the caller's buffer as it found it")
		}

		for name, e := range map[string]enclave.ByteAccess{"Move": moved, "Copy": copied} {
			if e.Size() != len(secret) {
				t.Errorf("%s: Size = %d, want %d", name, e.Size(), len(secret))
			}
			if ok, err := e.EqualTo([]byte(secret)); !ok || err != nil {
				t.Errorf("%s: EqualTo = (%t, %v), want (true, nil)", name, ok, err)
			}
			if ok, err := e.EqualTo([]byte(strings.ToUpper(secret))); ok || err != nil {
				t.Errorf("%s: EqualTo(same length, different content) = (%t, %v), want (false, nil)", name, ok, err)
			}
			if ok, err := e.EqualTo([]byte("short")); ok || err != nil {
				t.Errorf("%s: EqualTo(different length) = (%t, %v), want (false, nil)", name, ok, err)
			}
			if s := fmt.Sprint(e); strings.Contains(s, secret) || strings.Contains(s, secret[:8]) {
				t.Errorf("%s: String() leaks the material: %q", name, s)
			}
			// The borrow aliases the enclave's read-only pages (a write would fault).
			if err := e.WithBytes(func(b []byte) error {
				if string(b) != secret {
					t.Errorf("%s: WithBytes lent %d bytes that are not the material", name, len(b))
				}
				return nil
			}); err != nil {
				t.Errorf("%s: WithBytes = %v", name, err)
			}
			if err := e.Destroy(); err != nil {
				t.Fatalf("%s: Destroy: %v", name, err)
			}
			if e.IsAlive() {
				t.Errorf("%s: alive after Destroy", name)
			}
			if ok, err := e.EqualTo([]byte(secret)); ok || !errors.Is(err, enclave.ErrEnclaveDestroyed) {
				t.Errorf("%s: EqualTo after Destroy = (%t, %v), want (false, ErrEnclaveDestroyed)", name, ok, err)
			}
			if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
				t.Errorf("%s: WithBytes after Destroy = %v, want ErrEnclaveDestroyed", name, err)
			}
			if s := fmt.Sprint(e); !strings.Contains(strings.ToLower(s), "destroyed") {
				t.Errorf("%s: String() after Destroy = %q, want it to say so", name, s)
			}
		}

		// Empty material is refused by every constructor, before any locked
		// memory is requested.
		if _, err := enclave.NewMemory(nil); !errors.Is(err, enclave.ErrEmptyEnclave) {
			t.Errorf("NewMemory(nil) = %v, want ErrEmptyEnclave", err)
		}
		if _, err := enclave.NewMemoryCopy(nil); !errors.Is(err, enclave.ErrEmptyEnclave) {
			t.Errorf("NewMemoryCopy(nil) = %v, want ErrEmptyEnclave", err)
		}
		if _, err := enclave.NewMemorySized(0); !errors.Is(err, enclave.ErrInvalidSize) {
			t.Errorf("NewMemorySized(0) = %v, want ErrInvalidSize", err)
		}

		if n, err := enclave.WipeAll(context.Background()); n != 0 || err != nil {
			t.Fatalf("WipeAll = (%d, %v), want (0, nil)", n, err)
		}
	})
}

// TestSealing_KeyScheduleErasureReportsThisBuild pins that a build without
// GOEXPERIMENT=runtimesecret reports that it does not erase key schedules.
// make test-runtimesecret covers the erasing build.
func TestSealing_KeyScheduleErasureReportsThisBuild(t *testing.T) {
	if enclave.KeyScheduleErasure() {
		t.Fatal("KeyScheduleErasure() = true in a build without GOEXPERIMENT=runtimesecret")
	}
}

// TestMemoryEnclave_EnclaveErrorTypesRenderEveryValue pins that every value of the exported
// release and allocation error types, including the zero value, renders and
// unwraps to nothing it does not carry.
func TestMemoryEnclave_EnclaveErrorTypesRenderEveryValue(t *testing.T) {
	for _, e := range []error{&enclave.UnwipedReleaseError{}, &enclave.LockedMemoryError{}, &enclave.OpenError{},
		&enclave.SealerWipedError{}, &enclave.BackendNotRegisteredError{}, &enclave.BackendExistsError{},
		&enclave.ProbeError{}, &enclave.MemfdSecretError{}} {
		if msg := e.Error(); !strings.HasPrefix(msg, "enclave: ") {
			t.Errorf("%T{}.Error() = %q, want a message in the package's voice", e, msg)
		}
	}
	if errors.Unwrap(&enclave.LockedMemoryError{}) != nil {
		t.Error("a LockedMemoryError with no cause unwraps to something")
	}
	memfd := &enclave.MemfdSecretError{Cause: errors.ErrUnsupported}
	if !errors.Is(memfd, enclave.ErrMemfdSecretUnavailable) {
		t.Error("a MemfdSecretError does not match ErrMemfdSecretUnavailable")
	}
	if errors.Unwrap(memfd) != errors.ErrUnsupported {
		t.Error("a MemfdSecretError does not unwrap to its cause")
	}
}

// TestLockedMemoryBudget_ForceLimitRaisesHoldsAndRefuses: ForceLimit refuses a
// negative budget, leaves an equal one as it is, and grants a raise at once,
// reporting no excess on either.
func TestLockedMemoryBudget_ForceLimitRaisesHoldsAndRefuses(t *testing.T) {
	page := enclave.LockedSize(1)
	a, err := enclave.NewAllocator(2 * page)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if _, err := a.ForceLimit(-1); !errors.Is(err, enclave.ErrInvalidBudget) {
		t.Errorf("ForceLimit(-1) = %v, want ErrInvalidBudget", err)
	}
	if excess, err := a.ForceLimit(2 * page); excess != 0 || err != nil {
		t.Errorf("ForceLimit(equal) = (%d, %v), want (0, nil)", excess, err)
	}
	if excess, err := a.ForceLimit(4 * page); excess != 0 || err != nil {
		t.Errorf("ForceLimit(raise) = (%d, %v), want (0, nil)", excess, err)
	}
	if got := a.Limit(); got != 4*page {
		t.Errorf("Limit after the raise = %d, want %d", got, 4*page)
	}
	if got := a.Available(); got != 4*page {
		t.Errorf("Available after the raise = %d, want %d", got, 4*page)
	}
}

// TestMemoryEnclave_DestroyedEnclavesAnswerSafely pins that every accessor of
// a destroyed enclave, its Freezer reached through As included, returns its
// documented sentinel or zero value without touching unmapped memory.
func TestMemoryEnclave_DestroyedEnclavesAnswerSafely(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		e, err := enclave.NewMemorySized(32)
		if err != nil {
			t.Fatalf("NewMemorySized: %v", err)
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
		var f enclave.Freezer
		if !enclave.As(e, &f) {
			t.Fatalf("a destroyed enclave does not reach Freezer through As")
		}
		if err := f.Freeze(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("Freeze of a destroyed enclave = %v, want ErrEnclaveDestroyed", err)
		}
		if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
			t.Errorf("WithBytes of a destroyed enclave = %v, want ErrEnclaveDestroyed", err)
		}
	})
}

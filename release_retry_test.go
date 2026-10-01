// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"errors"
	"sync"
	"testing"
)

// errNotLocked is what installStrictUnlock returns for a second unlock of the
// same region: Windows' VirtualUnlock fails with ERROR_NOT_LOCKED on pages that
// are not locked, where Linux's munlock succeeds.
var errNotLocked = errors.New("VirtualUnlock: ERROR_NOT_LOCKED")

// installStrictUnlock replaces unlockMemory with one that has VirtualUnlock's
// semantics: the first unlock of a region goes through to the real call, and
// any later unlock of a region already unlocked is REFUSED with errNotLocked.
//
// Linux tolerates a repeated munlock, so without this a release path that
// unlocks again on every retry passes here and fails on Windows (#83). The
// seam is restored by t.Cleanup; register any cleanup that must run with the
// real unlock BEFORE calling this, since cleanups run last-in first-out.
func installStrictUnlock(t *testing.T) {
	t.Helper()
	prev := unlockMemory
	t.Cleanup(func() { unlockMemory = prev })

	var mu sync.Mutex
	unlocked := make(map[*byte]struct{})
	unlockMemory = func(b []byte) error {
		mu.Lock()
		defer mu.Unlock()
		if _, done := unlocked[&b[0]]; done {
			return errNotLocked
		}
		if err := prev(b); err != nil {
			return err
		}
		unlocked[&b[0]] = struct{}{}
		return nil
	}
}

// TestMapping_RetryAfterARefusedUnmapDoesNotUnlockAgain is the regression for
// the repeated-unlock finding in #83.
//
// release unlocked the pages on EVERY attempt. When the first attempt's munlock
// succeeded and its munmap was refused, the retry unlocked again — harmless on
// Linux, but on Windows VirtualUnlock refuses pages that are not locked, so
// every retry returned at the unlock and never reached the unmap again. The
// mapping, and any Allocator reservation behind it, was then held for the
// process lifetime however often DestroyErr or WipeAll retried.
//
// The held attempt must also report the pages as NOT locked, since the unlock
// that did succeed is the state the retry now trusts.
func TestMapping_RetryAfterARefusedUnmapDoesNotUnlockAgain(t *testing.T) {
	m, err := newMapping(32)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	prevFree := freeMemory
	t.Cleanup(func() {
		freeMemory = prevFree
		if m.memory != nil {
			_ = m.release()
		}
	})
	installStrictUnlock(t)

	frees := 0
	freeMemory = func(b []byte) error {
		frees++
		if frees == 1 {
			return errors.New("munmap: cannot allocate memory")
		}
		return prevFree(b)
	}

	err = m.release()
	if !pagesHeld(err) {
		t.Fatalf("release with a refused munmap = %v, want a held failure", err)
	}
	if lockedPagesHeld(err) {
		t.Errorf("lockedPagesHeld(%v) = true, want false: the munlock succeeded", err)
	}

	err = m.release()
	if errors.Is(err, errNotLocked) {
		t.Fatalf("the retry unlocked the region a second time and was refused (%v); on Windows the "+
			"mapping can then never be released", err)
	}
	if err != nil {
		t.Fatalf("retry = %v, want nil once the munmap is allowed", err)
	}
	if frees != 2 {
		t.Errorf("munmap attempted %d times, want 2: the retry never reached it", frees)
	}
	if m.memory != nil {
		t.Error("the mapping is still held after the retry released the pages")
	}
}

// TestRelease_RetryReturnsTheReservationUnderStrictUnlock is the same
// regression through both public retry paths, asserting what the defect cost a
// caller: the reservation. Under VirtualUnlock semantics an enclave whose
// munmap was refused once could never be released by DestroyErr or WipeAll,
// and its Allocator charge stayed with it.
func TestRelease_RetryReturnsTheReservationUnderStrictUnlock(t *testing.T) {
	for _, tc := range []struct {
		name  string
		retry func(t *testing.T, e *MemoryEnclave, wantHeld bool)
	}{
		{"DestroyErr", func(t *testing.T, e *MemoryEnclave, wantHeld bool) {
			err := e.DestroyErr()
			if got := pagesHeld(err); got != wantHeld {
				t.Fatalf("DestroyErr = %v, pagesHeld %v, want %v", err, got, wantHeld)
			}
			if !wantHeld && err != nil {
				t.Fatalf("DestroyErr = %v, want nil", err)
			}
		}},
		{"WipeAll", func(t *testing.T, _ *MemoryEnclave, wantHeld bool) {
			want := 0
			if wantHeld {
				want = 1
			}
			if remaining := sweep(t); remaining != want {
				t.Fatalf("WipeAll = %d, want %d", remaining, want)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if remaining := sweep(t); remaining != 0 {
				t.Fatalf("the process already holds %d unwipeable enclaves; this test needs a clean ledger", remaining)
			}
			a, err := NewAllocator(4 * pageSize)
			if err != nil {
				t.Fatalf("NewAllocator: %v", err)
			}
			e, err := a.NewSized(32)
			if err != nil {
				t.Fatalf("Allocator.NewSized: %v", err)
			}

			prevFree := freeMemory
			t.Cleanup(func() {
				freeMemory = prevFree
				_, _ = WipeAll()
			})
			installStrictUnlock(t)
			freeMemory = func([]byte) error { return errors.New("munmap: cannot allocate memory") }

			tc.retry(t, e, true)
			if used := a.InUse(); used != pageSize {
				t.Errorf("InUse = %d with the pages still mapped, want %d", used, pageSize)
			}

			freeMemory = prevFree
			tc.retry(t, e, false)
			if used := a.InUse(); used != 0 {
				t.Errorf("InUse = %d after the retry, want 0: the reservation is stranded behind a "+
					"release that can never reach the munmap", used)
			}
			if isRegistered(e) {
				t.Error("the enclave is still on the ledger after the retry")
			}
		})
	}
}

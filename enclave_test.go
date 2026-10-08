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
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

func TestNewMemoryEnclave_HoldsMaterial(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("private-key-material"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	defer e.Destroy()

	// Compared in place: neither a string conversion nor a %q may carry the
	// material onto the heap or into the test log.
	if err := e.WithBytes(func(got []byte) error {
		if !bytes.Equal(got, []byte("private-key-material")) {
			t.Errorf("WithBytes lent a %d-byte view that does not hold the material it was built from", len(got))
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	if e.Size() != len("private-key-material") {
		t.Errorf("Size = %d, want %d", e.Size(), len("private-key-material"))
	}
	if !e.IsAlive() {
		t.Error("IsAlive = false, want true")
	}
}

func TestNewMemoryEnclave_WipesSource(t *testing.T) {
	src := []byte("wipe-me-completely")
	want := make([]byte, len(src))

	e, err := NewMemoryEnclave(src)
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	defer e.Destroy()

	if !bytes.Equal(src, want) {
		t.Errorf("source not wiped: got %q, want all zeroes", src)
	}
}

func TestNewMemoryEnclave_Empty(t *testing.T) {
	for name, in := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			e, err := NewMemoryEnclave(in)
			if !errors.Is(err, ErrEmptyEnclave) {
				t.Errorf("err = %v, want ErrEmptyEnclave", err)
			}
			if e != nil {
				t.Error("enclave should be nil on error")
			}
		})
	}
}

// TestNewMemoryEnclaveCopy_LeavesTheSourceIntact pins that the copy constructor
// leaves its source intact while NewMemoryEnclave wipes identical bytes. The two
// constructors share one body, so only both halves together show they differ.
func TestNewMemoryEnclaveCopy_LeavesTheSourceIntact(t *testing.T) {
	const material = "caller-owned-credential"

	copied := []byte(material)
	e, err := NewMemoryEnclaveCopy(copied)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}
	defer e.Destroy()

	if string(copied) != material {
		t.Errorf("source = %q after NewMemoryEnclaveCopy, want it untouched (%q)", copied, material)
	}
	if !holds(e, []byte(material)) {
		t.Error("the enclave does not hold the material it was handed")
	}
	if e.Size() != len(material) {
		t.Errorf("Size = %d, want %d", e.Size(), len(material))
	}

	moved := []byte(material)
	m, err := NewMemoryEnclave(moved)
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	defer m.Destroy()

	if !bytes.Equal(moved, make([]byte, len(material))) {
		t.Errorf("source = %q after NewMemoryEnclave, want it wiped", moved)
	}
}

// TestNewMemoryEnclaveCopy_IsIndependentOfTheSource pins that the copy does not
// alias the caller's slice: neither writing nor wiping the source afterwards
// reaches the enclave's material.
func TestNewMemoryEnclaveCopy_IsIndependentOfTheSource(t *testing.T) {
	material := []byte("independent-material")

	src := append([]byte(nil), material...)
	e, err := NewMemoryEnclaveCopy(src)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}
	defer e.Destroy()

	src[0] = 0xFF
	if !holds(e, material) {
		t.Error("mutating the source changed the enclave: the copy aliases it")
	}

	Wipe(src)
	if !holds(e, material) {
		t.Error("wiping the source emptied the enclave: the copy aliases it")
	}
}

// TestNewMemoryEnclaveCopy_PagesAreFrozen pins that a copy-constructed enclave
// is read-only, by reading the protection state in-process; the fault itself is
// exercised in a subprocess by TestMemoryEnclave_CopyConstructedPagesAreReadOnly.
// A sized enclave is the control, so the field is shown able to read true.
func TestNewMemoryEnclaveCopy_PagesAreFrozen(t *testing.T) {
	e, err := NewMemoryEnclaveCopy([]byte("frozen-after-copy"))
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}
	defer e.Destroy()

	if e.m.mutable {
		t.Error("a copy-constructed enclave is writable; a stray write would corrupt it silently instead of faulting")
	}

	// The control: a sized enclave must be writable or its fill would fault.
	sized, err := NewMemoryEnclaveSized(16)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer sized.Destroy()

	if !sized.m.mutable {
		t.Error("a sized enclave is frozen; the fill path would fault")
	}
}

func TestNewMemoryEnclaveCopy_Empty(t *testing.T) {
	for name, in := range map[string][]byte{"nil": nil, "empty": {}} {
		t.Run(name, func(t *testing.T) {
			e, err := NewMemoryEnclaveCopy(in)
			if !errors.Is(err, ErrEmptyEnclave) {
				t.Errorf("err = %v, want ErrEmptyEnclave", err)
			}
			if e != nil {
				t.Error("enclave should be nil on error")
			}
		})
	}
}

// TestNewMemoryEnclaveCopy_IsPublishedToTheLedger pins that the copy
// constructor registers its enclave, so WipeAll reaches it at shutdown.
func TestNewMemoryEnclaveCopy_IsPublishedToTheLedger(t *testing.T) {
	material := []byte("swept-at-shutdown")

	before := liveCount()

	e, err := NewMemoryEnclaveCopy(material)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}
	if got := liveCount(); got != before+1 {
		t.Fatalf("ledger holds %d, want %d: construction did not register", got, before+1)
	}

	if remaining := sweep(t); remaining != 0 {
		t.Errorf("WipeAll left %d enclaves, want 0", remaining)
	}
	if e.IsAlive() {
		t.Error("the enclave survived WipeAll")
	}
}

func TestMemoryEnclave_Destroy(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("transient"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}

	e.Destroy()
	e.Destroy() // idempotent

	if e.IsAlive() {
		t.Error("IsAlive = true after Destroy")
	}
	if e.Size() != 0 {
		t.Errorf("Size = %d after Destroy, want 0", e.Size())
	}
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("WithBytes err = %v, want ErrEnclaveDestroyed", err)
	}
	if ok, err := e.EqualTo([]byte("transient")); ok || !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("EqualTo = (%t, %v) on destroyed enclave, want (false, ErrEnclaveDestroyed)", ok, err)
	}
}

func TestMemoryEnclave_NilReceiver(t *testing.T) {
	var e *MemoryEnclave

	e.Destroy() // must not panic

	if e.IsAlive() {
		t.Error("IsAlive = true on nil enclave")
	}
	if e.Size() != 0 {
		t.Errorf("Size = %d on nil enclave, want 0", e.Size())
	}
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("WithBytes err = %v, want ErrEnclaveDestroyed", err)
	}
	if ok, err := e.EqualTo(nil); ok || !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("EqualTo = (%t, %v) on nil enclave, want (false, ErrEnclaveDestroyed)", ok, err)
	}
	if got := e.String(); got != "MemoryEnclave(destroyed)" {
		t.Errorf("String = %q", got)
	}
}

func TestMemoryEnclave_WithBytes(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("borrowed"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	defer e.Destroy()

	// The verdict is taken INSIDE the borrow; the material never leaves it.
	var saw bool
	if err := e.WithBytes(func(b []byte) error {
		saw = bytes.Equal(b, []byte("borrowed"))
		return nil
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	if !saw {
		t.Error("fn's view did not hold the material the enclave was built from")
	}

	sentinel := errors.New("from fn")
	if err := e.WithBytes(func([]byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Errorf("WithBytes err = %v, want the fn's error", err)
	}
}

func TestMemoryEnclave_EqualTo(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("compare-me"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	defer e.Destroy()

	for _, tc := range []struct {
		other []byte
		want  bool
	}{
		{[]byte("compare-me"), true},
		{[]byte("compare-mE"), false},
		{[]byte("compare"), false},
		{nil, false},
	} {
		if got, err := e.EqualTo(tc.other); got != tc.want || err != nil {
			t.Errorf("EqualTo(%q) = (%t, %v), want (%t, nil)", tc.other, got, err, tc.want)
		}
	}
}

// holds reports whether e is alive and holds exactly b.
func holds(e *MemoryEnclave, b []byte) bool {
	ok, err := e.EqualTo(b)
	return err == nil && ok
}

func TestMemoryEnclave_StringRedacts(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("do-not-print-me"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	defer e.Destroy()

	got := e.String()
	if strings.Contains(got, "do-not-print-me") {
		t.Errorf("String leaked the material: %q", got)
	}
	if got != "MemoryEnclave(redacted)" {
		t.Errorf("String = %q, want MemoryEnclave(redacted)", got)
	}
}

func TestMemoryEnclave_ConcurrentAccess(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("concurrent"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Either the material or ErrEnclaveDestroyed is correct.
			if ok, err := e.EqualTo([]byte("concurrent")); err == nil && !ok {
				t.Error("EqualTo found an alive enclave not holding the material")
			}
			_ = e.Size()
			_ = e.IsAlive()
			_ = e.String()
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.Destroy()
	}()
	wg.Wait()

	if e.IsAlive() {
		t.Error("IsAlive = true after concurrent Destroy")
	}
}

// TestMemoryEnclave_DestroyWaitsForInFlightReader pins that Destroy blocks
// until an in-flight scoped borrow returns. The property is the ordering, not
// the IsAlive flag.
func TestMemoryEnclave_DestroyWaitsForInFlightReader(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("private-key-material"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}

	var order, readerExit, destroyExit atomic.Int32

	borrowed := make(chan struct{})
	release := make(chan struct{})
	destroyed := make(chan struct{})

	go func() {
		_ = e.WithBytes(func(b []byte) error {
			close(borrowed)
			<-release
			// Recorded inside the borrow, while the read lock is held, so it
			// happens-before Destroy can take the write lock. After WithBytes
			// returns it would be ordered by scheduling, not by the lock.
			readerExit.Store(order.Add(1))
			return nil
		})
	}()

	<-borrowed

	go func() {
		e.Destroy()
		destroyExit.Store(order.Add(1))
		close(destroyed)
	}()

	// Destroy must not complete while the reader is parked inside its borrow.
	select {
	case <-destroyed:
		t.Fatal("Destroy completed while a borrow was still in flight")
	case <-time.After(250 * time.Millisecond):
	}

	close(release)

	select {
	case <-destroyed:
	case <-time.After(10 * time.Second):
		t.Fatal("Destroy did not complete after the borrow was released")
	}

	if readerExit.Load() != 1 || destroyExit.Load() != 2 {
		t.Fatalf("reader exited at %d and Destroy at %d, want 1 then 2", readerExit.Load(), destroyExit.Load())
	}
	if e.IsAlive() {
		t.Error("enclave still alive after Destroy")
	}
}

// TestMemoryEnclave_ConcurrentReadersAndDestroy runs every scoped-borrow path
// against a concurrent Destroy. Under -race this catches an access that
// escapes the enclave's lock; without it, it still catches a read that
// dereferences a destroyed buffer.
func TestMemoryEnclave_ConcurrentReadersAndDestroy(t *testing.T) {
	for i := 0; i < 50; i++ {
		e, err := NewMemoryEnclave([]byte("private-key-material"))
		if err != nil {
			t.Fatalf("NewMemoryEnclave: %v", err)
		}

		var wg sync.WaitGroup
		for r := 0; r < 8; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = e.WithBytes(func(b []byte) error { return nil })
				_ = holds(e, []byte("private-key-material"))
				_ = e.Size()
				_ = e.String()
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Destroy()
		}()

		wg.Wait()

		if e.IsAlive() {
			t.Fatal("enclave alive after Destroy")
		}
	}
}

// TestLockedMemoryError pins the typed error's contract: it matches
// ErrLockedMemoryUnavailable, keeps the diagnostic text, and unwraps a cause
// that is an error.
// TestEqualToSeparatesMismatchFromDestroyed pins that a mismatch is
// (false, nil) and a missing enclave is (false, ErrEnclaveDestroyed): an
// inverted test must never read a destroyed enclave as a definite mismatch.
func TestEqualToSeparatesMismatchFromDestroyed(t *testing.T) {
	const material = "the real material"

	t.Run("match", func(t *testing.T) {
		e, err := NewMemoryEnclave([]byte(material))
		if err != nil {
			t.Fatalf("NewMemoryEnclave: %v", err)
		}
		defer e.Destroy()

		equal, err := e.EqualTo([]byte(material))
		if err != nil {
			t.Fatalf("EqualTo on a live enclave = %v, want no error", err)
		}
		if !equal {
			t.Error("EqualTo reported a mismatch for identical material")
		}
	})

	t.Run("genuine mismatch is (false, nil)", func(t *testing.T) {
		e, err := NewMemoryEnclave([]byte(material))
		if err != nil {
			t.Fatalf("NewMemoryEnclave: %v", err)
		}
		defer e.Destroy()

		equal, err := e.EqualTo([]byte("something else"))
		if err != nil {
			t.Fatalf("EqualTo = %v, want no error: the comparison RAN, it "+
				"simply did not match", err)
		}
		if equal {
			t.Error("EqualTo reported equal for different material")
		}
	})

	t.Run("destroyed is (false, ErrEnclaveDestroyed)", func(t *testing.T) {
		e, err := NewMemoryEnclave([]byte(material))
		if err != nil {
			t.Fatalf("NewMemoryEnclave: %v", err)
		}
		e.Destroy()

		equal, err := e.EqualTo([]byte(material))
		if !errors.Is(err, ErrEnclaveDestroyed) {
			t.Fatalf("EqualTo on a destroyed enclave = (%v, %v), want "+
				"ErrEnclaveDestroyed: a caller that cannot distinguish this "+
				"from a mismatch is acting on a fact it does not have", equal, err)
		}
		if equal {
			t.Error("EqualTo reported equal for a destroyed enclave")
		}
	})

	t.Run("nil receiver", func(t *testing.T) {
		var e *MemoryEnclave
		equal, err := e.EqualTo([]byte(material))
		if !errors.Is(err, ErrEnclaveDestroyed) || equal {
			t.Fatalf("nil EqualTo = (%v, %v), want (false, ErrEnclaveDestroyed)", equal, err)
		}
	})
}

// panicValue runs fn and returns what it panicked with, or nil.
func panicValue(fn func()) (r any) {
	defer func() { r = recover() }()
	fn()
	return nil
}

// generateInto fills the sized enclave e from the CSPRNG and copies the result,
// from inside the same borrow, into a second locked enclave (the yardstick), so
// the material never exists outside locked memory. The caller must Destroy the
// yardstick.
func generateInto(t *testing.T, e *MemoryEnclave) *MemoryEnclave {
	t.Helper()
	yardstick, err := NewMemoryEnclaveSized(e.Size())
	if err != nil {
		t.Fatalf("allocating the yardstick enclave: %v", err)
	}
	var zero bool
	if err := e.WithBytes(func(key []byte) error {
		// The CSPRNG writes straight into the locked pages.
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return err
		}
		zero = memscan.AllZero(key)
		return yardstick.WithBytes(func(w []byte) error {
			copy(w, key)
			return nil
		})
	}); err != nil {
		_ = yardstick.Destroy()
		t.Fatalf("fill: %v", err)
	}
	if zero {
		_ = yardstick.Destroy()
		t.Fatal("the generator produced all zeroes; every comparison against it would be vacuous")
	}
	// Re-read both through fresh borrows: if a borrow handed out a detached
	// copy, both would read zero and every later comparison would be vacuous.
	var storedZero, yardstickZero bool
	if err := e.WithBytes(func(b []byte) error { storedZero = memscan.AllZero(b); return nil }); err != nil {
		_ = yardstick.Destroy()
		t.Fatalf("re-reading the filled enclave: %v", err)
	}
	if err := yardstick.WithBytes(func(b []byte) error { yardstickZero = memscan.AllZero(b); return nil }); err != nil {
		_ = yardstick.Destroy()
		t.Fatalf("re-reading the yardstick: %v", err)
	}
	if storedZero || yardstickZero {
		_ = yardstick.Destroy()
		t.Fatalf("the fill did not persist (enclave all-zero %t, yardstick all-zero %t): a borrow wrote to something other than the locked pages", storedZero, yardstickZero)
	}
	return yardstick
}

// sameMaterial reports whether a and b hold identical material, comparing
// through a nested borrow and a's EqualTo so nothing leaves locked memory.
func sameMaterial(t *testing.T, a, b *MemoryEnclave) bool {
	t.Helper()
	var same bool
	if err := b.WithBytes(func(w []byte) error {
		same = holds(a, w)
		return nil
	}); err != nil {
		t.Fatalf("borrowing the yardstick: %v", err)
	}
	return same
}

// isRegistered reports whether e is still on the shutdown ledger.
func isRegistered(e *MemoryEnclave) bool {
	registryMu.Lock()
	defer registryMu.Unlock()
	_, ok := live[e]
	return ok
}

// TestDestroy_ReleaseFailureIsReturnedNotPanicked pins the retained-for-retry
// contract when the munlock after a successful wipe is refused: Destroy returns
// ErrLockedMemoryUnavailable without panicking, keeps the mapping, reads
// destroyed, stays on the ledger, keeps the Allocator charge, and a retry once
// the refusal lifts releases everything.
func TestDestroy_ReleaseFailureIsReturnedNotPanicked(t *testing.T) {
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.New([]byte("material whose pages the kernel will not take back"))
	if err != nil {
		t.Fatalf("Allocator.New: %v", err)
	}

	denied := errors.New("munlock: cannot allocate memory")
	// Registered first, so the enclave is destroyed after the seam is restored.
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.Destroy()
		}
	})
	prev := swapSeam(t, &unlockMemory, func([]byte) error { return denied })

	var derr error
	if r := panicValue(func() { derr = e.Destroy() }); r != nil {
		t.Fatalf("Destroy panicked with %v on a release failure that is not corruption", r)
	}
	if !errors.Is(derr, ErrLockedMemoryUnavailable) || !errors.Is(derr, denied) {
		t.Fatalf("Destroy = %v, want the refused munlock as ErrLockedMemoryUnavailable", derr)
	}
	if errors.Is(derr, ErrEnclaveCorrupted) {
		t.Errorf("Destroy = %v reports corruption that did not happen", derr)
	}
	if e.m == nil || e.m.memory == nil {
		t.Fatal("the mapping was dropped although its pages are still held; there is no handle to retry through")
	}
	if e.IsAlive() {
		t.Error("the enclave reads alive although its material was wiped")
	}
	if !isRegistered(e) {
		t.Error("the enclave left the ledger with its pages still held; WipeAll can no longer retry it")
	}
	if used := a.InUse(); used != pageSize {
		t.Errorf("InUse = %d after a failed release, want %d: the kernel still holds the pages", used, pageSize)
	}

	// A retry under the same refusal reports it again without panicking.
	if r := panicValue(func() { derr = e.Destroy() }); r != nil {
		t.Fatalf("a retried Destroy panicked with %v on a release failure that is not corruption", r)
	}
	if !errors.Is(derr, ErrLockedMemoryUnavailable) {
		t.Fatalf("a retried Destroy under the same refusal = %v, want ErrLockedMemoryUnavailable again", derr)
	}

	unlockMemory = prev
	if derr := e.Destroy(); derr != nil {
		t.Fatalf("retried Destroy = %v, want nil once the refusal lifted", derr)
	}
	if e.m != nil {
		t.Error("the mapping is still held after a successful retry")
	}
	if isRegistered(e) {
		t.Error("the enclave is still on the ledger after its pages went back")
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after the retry released the pages, want 0", used)
	}
}

// TestDestroy_CorruptionIsReturnedAndReported pins Destroy's contract for a
// failed canary: it returns ErrEnclaveCorrupted rather than panicking, only
// after wiping, unmapping and returning the reservation, and the next WipeAll
// reports it once even though the caller's error was discarded.
func TestDestroy_CorruptionIsReturnedAndReported(t *testing.T) {
	requireCleanLedger(t)
	forgetDestroyedCorruption(t)

	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.NewSized(64)
	if err != nil {
		t.Fatalf("Allocator.NewSized: %v", err)
	}
	if len(e.m.canary) == 0 {
		t.Fatal("no canary slack for this size; the test would be vacuous")
	}
	e.m.canary[0] ^= 0xFF

	var derr error
	if r := panicValue(func() { derr = e.Destroy() }); r != nil {
		t.Fatalf("Destroy panicked with %v on a corrupted canary, want a returned error", r)
	}
	if !errors.Is(derr, ErrEnclaveCorrupted) {
		t.Fatalf("Destroy = %v, want ErrEnclaveCorrupted", derr)
	}
	if e.IsAlive() || e.m != nil {
		t.Error("the corrupted enclave was not released")
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after a corrupted Destroy, want 0: the pages went back", used)
	}
	if isRegistered(e) {
		t.Error("the corrupted enclave is still on the ledger after its pages went back")
	}
	if again := e.Destroy(); again != nil {
		t.Errorf("a second Destroy = %v, want nil: nothing is left to release", again)
	}

	remaining, err := WipeAll(context.Background())
	var se *SweepError
	if remaining != 0 || !errors.As(err, &se) || se.Corrupt != 1 {
		t.Fatalf("WipeAll after a corrupted Destroy = (%d, %v), want (0, SweepError{Corrupt:1})", remaining, err)
	}
	if remaining, err := WipeAll(context.Background()); remaining != 0 || err != nil {
		t.Errorf("a second WipeAll = (%d, %v), want (0, nil): a detection is reported by one sweep", remaining, err)
	}
}

// TestDestroy_CorruptionSurvivesAFailedRelease pins that a corrupted canary
// whose release is also refused returns both ErrEnclaveCorrupted and
// ErrLockedMemoryUnavailable, keeping the mapping and charge, and that the retry
// which releases the pages still reports the corruption.
func TestDestroy_CorruptionSurvivesAFailedRelease(t *testing.T) {
	forgetDestroyedCorruption(t)

	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := a.NewSized(32)
	if err != nil {
		t.Fatalf("Allocator.NewSized: %v", err)
	}
	if len(e.m.canary) == 0 {
		t.Fatal("a 32-byte enclave has no canary slack; this test would be vacuous")
	}
	// A sized enclave is writable, so this is a store rather than a fault.
	e.m.canary[len(e.m.canary)-1] ^= 0xFF

	denied := errors.New("munmap: cannot allocate memory")
	// Registered first, so the enclave is destroyed after the seams are restored.
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.Destroy()
		}
	})
	// VirtualUnlock semantics: the first attempt's munlock succeeds, so a retry
	// that unlocks again is refused on Windows before it reaches the munmap.
	installStrictUnlock(t)
	prev := swapSeam(t, &unmapMemory, func([]byte) error { return denied })

	derr := e.Destroy()
	if !errors.Is(derr, ErrEnclaveCorrupted) || !errors.Is(derr, ErrLockedMemoryUnavailable) {
		t.Fatalf("Destroy over a corrupted canary with a refused munmap = %v, "+
			"want ErrEnclaveCorrupted and ErrLockedMemoryUnavailable", derr)
	}
	if e.m == nil || e.m.memory == nil {
		t.Fatal("the mapping was dropped although its pages are still mapped")
	}
	if used := a.InUse(); used != pageSize {
		t.Errorf("InUse = %d with the pages still mapped, want %d", used, pageSize)
	}
	if !isRegistered(e) {
		t.Error("the enclave left the ledger with its pages still mapped")
	}

	unmapMemory = prev
	if derr := e.Destroy(); !errors.Is(derr, ErrEnclaveCorrupted) || errors.Is(derr, ErrLockedMemoryUnavailable) {
		t.Fatalf("the retry that released the pages = %v, want ErrEnclaveCorrupted alone: "+
			"the corruption detected on the first attempt was lost", derr)
	}
	if e.m != nil {
		t.Error("the mapping is still held after the retry released the pages")
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("InUse = %d after the pages went back, want 0", used)
	}
	if isRegistered(e) {
		t.Error("the enclave is still on the ledger after its pages went back")
	}
}

// forgetDestroyedCorruption clears, at cleanup, the corruption reports a test's
// Destroy calls leave for the next WipeAll, so they cannot leak into another
// test's sweep.
func forgetDestroyedCorruption(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		registryMu.Lock()
		clear(corruptNoted)
		registryMu.Unlock()
	})
}

// TestNewMemoryEnclaveSized_ZeroedAndSized pins that the enclave is exactly n
// bytes and every byte is zero.
func TestNewMemoryEnclaveSized_ZeroedAndSized(t *testing.T) {
	for _, n := range []int{1, 32, 4096, 8192} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			e, err := NewMemoryEnclaveSized(n)
			if err != nil {
				t.Fatalf("NewMemoryEnclaveSized(%d): %v", n, err)
			}
			defer e.Destroy()

			if e.Size() != n {
				t.Errorf("Size = %d, want %d", e.Size(), n)
			}
			if !e.IsAlive() {
				t.Error("IsAlive = false on a fresh enclave")
			}
			if err := e.WithBytes(func(b []byte) error {
				if len(b) != n {
					return fmt.Errorf("borrow length = %d, want %d", len(b), n)
				}
				for i, c := range b {
					if c != 0 {
						return fmt.Errorf("byte %d = %#x, want the region zeroed", i, c)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestNewMemoryEnclaveSized_FillsInPlace pins generate-in-place as aliasing:
// material written through one borrow is visible through the next. A borrow
// that handed out a copy would leave the second borrow reading zeroes.
func TestNewMemoryEnclaveSized_FillsInPlace(t *testing.T) {
	const n = 32

	e, err := NewMemoryEnclaveSized(n)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer e.Destroy()

	// The yardstick is a second locked enclave; a []byte one would be the
	// heap copy this constructor exists to prevent.
	want := generateInto(t, e)
	defer want.Destroy()

	// A separate borrow: if the first wrote to a copy, this reads zeroes.
	var same bool
	if err := e.WithBytes(func(b []byte) error {
		return want.WithBytes(func(w []byte) error {
			same = bytes.Equal(b, w)
			return nil
		})
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !same {
		t.Error("a second borrow saw something other than the material written by the first")
	}

	// EqualTo reads the same storage through the locked accessor.
	if !sameMaterial(t, e, want) {
		t.Error("EqualTo = false for the material generated into the enclave")
	}
}

// TestNewMemoryEnclaveSized_RejectsNonPositive pins that a non-positive size is
// refused with ErrInvalidSize before any mapping is attempted; reaching the
// allocator would surface as ErrLockedMemoryUnavailable instead.
func TestNewMemoryEnclaveSized_RejectsNonPositive(t *testing.T) {
	for _, n := range []int{0, -1, -4096} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			e, err := NewMemoryEnclaveSized(n)
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("err = %v, want ErrInvalidSize", err)
			}
			if errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Error("the request reached memguard; the size guard did not run first")
			}
			if e != nil {
				t.Error("a non-nil enclave was returned on error")
			}
		})
	}
}

// TestNewMemoryEnclaveSized_Lifecycle pins the destroyed contract for a filled
// sized enclave: every accessor reports ErrEnclaveDestroyed.
func TestNewMemoryEnclaveSized_Lifecycle(t *testing.T) {
	e, err := NewMemoryEnclaveSized(16)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}

	material := bytes.Repeat([]byte{0xA5}, 16)
	if err := e.WithBytes(func(b []byte) error {
		copy(b, material)
		return nil
	}); err != nil {
		t.Fatalf("fill: %v", err)
	}
	if !holds(e, material) {
		t.Fatal("EqualTo = false immediately after the fill")
	}

	e.Destroy()
	e.Destroy() // idempotent

	if e.IsAlive() {
		t.Error("IsAlive = true after Destroy")
	}
	if e.Size() != 0 {
		t.Errorf("Size = %d after Destroy, want 0", e.Size())
	}
	if err := e.WithBytes(func([]byte) error { return nil }); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("WithBytes err = %v, want ErrEnclaveDestroyed", err)
	}
	if holds(e, material) {
		t.Error("EqualTo = true on a destroyed enclave")
	}
}

// TestNewMemoryEnclaveSized_ConcurrentBorrowsAndDestroy runs the scoped-borrow
// paths of a filled sized enclave against a concurrent Destroy. Under -race it
// catches an access that escapes the enclave's lock.
func TestNewMemoryEnclaveSized_ConcurrentBorrowsAndDestroy(t *testing.T) {
	material := bytes.Repeat([]byte{0x5A}, 24)

	for i := 0; i < 50; i++ {
		e, err := NewMemoryEnclaveSized(len(material))
		if err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
		}
		if err := e.WithBytes(func(b []byte) error {
			copy(b, material)
			return nil
		}); err != nil {
			t.Fatalf("fill: %v", err)
		}

		var wg sync.WaitGroup
		for r := 0; r < 8; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = e.WithBytes(func(b []byte) error {
					// Either the material or a destroyed enclave is correct.
					if len(b) != 0 && !bytes.Equal(b, material) {
						t.Errorf("a %d-byte borrow saw neither the material nor a destroyed enclave", len(b))
					}
					return nil
				})
				_ = holds(e, material)
				_ = e.Size()
				_ = e.IsAlive()
				_ = e.String()
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			e.Destroy()
		}()

		wg.Wait()

		if e.IsAlive() {
			t.Fatal("enclave alive after Destroy")
		}
	}
}

func TestAllocator_NewSized_Admits(t *testing.T) {
	limit := 4 * pageSize
	a, err := NewAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	const n = 48
	e, err := a.NewSized(n)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}
	defer e.Destroy()

	// Charged the page it actually locks, not the 48 bytes requested.
	if a.InUse() != pageSize {
		t.Errorf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
	if a.Available() != limit-pageSize {
		t.Errorf("Available = %d, want %d", a.Available(), limit-pageSize)
	}
	if e.Size() != n {
		t.Errorf("Size = %d, want %d", e.Size(), n)
	}

	want := generateInto(t, e)
	defer want.Destroy()
	if !sameMaterial(t, e, want) {
		t.Error("an admitted sized enclave did not hold what was generated into it")
	}
}

// TestAllocator_NewSized_RefusesOverBudget pins that over-budget NewSized is
// refused with ErrBudgetExhausted, returns no enclave, and leaves the counter
// untouched. TestAllocator_NewSized_RefusalNeverAttemptsMapping (Linux) proves
// the refusal precedes the mapping.
func TestAllocator_NewSized_RefusesOverBudget(t *testing.T) {
	// One page of budget holds exactly one enclave, however small.
	a, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	first, err := a.NewSized(24)
	if err != nil {
		t.Fatalf("first NewSized: %v", err)
	}
	defer first.Destroy()

	before := a.InUse()
	e, err := a.NewSized(16)
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("over-budget NewSized err = %v, want ErrBudgetExhausted", err)
	}
	if e != nil {
		t.Error("over-budget NewSized returned a non-nil enclave")
	}
	if a.InUse() != before {
		t.Errorf("InUse = %d after refusal, want unchanged %d", a.InUse(), before)
	}

	var be *BudgetError
	if !errors.As(err, &be) {
		t.Fatalf("err is not a *BudgetError: %v", err)
	}
	// Locked bytes throughout: 16 bytes of material costs a page.
	if be.Requested != pageSize || be.Limit != pageSize || be.InUse != pageSize {
		t.Errorf("BudgetError = %+v, want Requested=InUse=Limit=%d", be, pageSize)
	}
}

// TestAllocator_NewSized_RejectsNonPositive pins that an impossible size is
// refused with ErrInvalidSize before admission: nothing is charged.
func TestAllocator_NewSized_RejectsNonPositive(t *testing.T) {
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	for _, n := range []int{0, -1, -4096} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			e, err := a.NewSized(n)
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("err = %v, want ErrInvalidSize", err)
			}
			if errors.Is(err, ErrBudgetExhausted) || errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Errorf("err = %v; the size guard did not run first", err)
			}
			if e != nil {
				t.Error("a non-nil enclave was returned on error")
			}
			if a.InUse() != 0 {
				t.Errorf("InUse = %d after an invalid size, want 0 (no reservation)", a.InUse())
			}
		})
	}
}

// TestAllocator_reserve_RefusesNonPositive pins reserve's counter invariant
// directly. Through NewSized a negative charge would be refunded within the
// call and InUse would read 0 either way, hiding the window in which a
// concurrent allocation could overshoot the limit.
func TestAllocator_reserve_RefusesNonPositive(t *testing.T) {
	limit := 16 * pageSize
	a, err := NewAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	for _, n := range []int64{0, -1, -4096} {
		t.Run(fmt.Sprintf("%d", n), func(t *testing.T) {
			if _, err := a.reserve(n); !errors.Is(err, ErrInvalidSize) {
				t.Errorf("reserve(%d) = %v, want ErrInvalidSize", n, err)
			}
			if got := a.InUse(); got != 0 {
				t.Errorf("InUse = %d after reserve(%d), want 0 (the counter was touched)", got, n)
			}
			if got := a.Available(); got != limit {
				t.Errorf("Available = %d after reserve(%d), want the full %d", got, n, limit)
			}
		})
	}

	// A legitimate reservation is still admitted and charged a whole page.
	charge, err := a.reserve(64)
	if err != nil {
		t.Fatalf("reserve(64) after the refusals: %v", err)
	}
	if charge != pageSize {
		t.Errorf("reserve(64) charged %d, want one page (%d)", charge, pageSize)
	}
	if a.InUse() != pageSize {
		t.Errorf("InUse = %d, want %d", a.InUse(), pageSize)
	}
}

// TestLockedSize pins the accounting unit: an enclave costs its size rounded up
// to a whole page, and a size no enclave can have costs 0.
func TestLockedSize(t *testing.T) {
	p := int(pageSize)
	for _, tc := range []struct {
		in   int
		want int64
	}{
		{1, pageSize},
		{32, pageSize},
		{p - 1, pageSize},
		{p, pageSize},
		{p + 1, 2 * pageSize},
		{2 * p, 2 * pageSize},
		{2*p + 1, 3 * pageSize},
	} {
		if got := LockedSize(tc.in); got != tc.want {
			t.Errorf("LockedSize(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}

	// Not a size any enclave can have.
	for _, n := range []int{0, -1, -4096} {
		if got := LockedSize(n); got != 0 {
			t.Errorf("LockedSize(%d) = %d, want 0", n, got)
		}
	}

	// The mapping is the data region plus two guard pages in int arithmetic,
	// so the largest constructible enclave stops two pages short of maxInt.
	maxIntV := int(^uint(0) >> 1)
	if got := LockedSize(maxIntV); got != 0 {
		t.Errorf("LockedSize(maxInt) = %d, want 0", got)
	}
	if got := LockedSize(maxIntV - int(pageSize)); got != 0 {
		t.Errorf("LockedSize(maxInt-page) = %d, want 0 (the mapping needs two guard pages too)", got)
	}

	// The boundary: the largest size that fits with its guard pages, and one past it.
	largest := int((maxInt - 2*pageSize) / pageSize * pageSize)
	if got := LockedSize(largest); got != int64(largest) {
		t.Errorf("LockedSize(largest constructible) = %d, want %d", got, largest)
	}
	if got := LockedSize(largest + 1); got != 0 {
		t.Errorf("LockedSize(largest+1) = %d, want 0", got)
	}
}

// TestSizedConstructors_RefuseUnmappableSizes pins that both sized
// constructors refuse a size whose mapping (data region plus two guard pages)
// overflows int, with ErrInvalidSize and before any mapping is attempted. An
// unrelated canary enclave must survive. The budget is large enough that
// admission cannot be what refuses.
func TestSizedConstructors_RefuseUnmappableSizes(t *testing.T) {
	maxIntV := int(^uint(0) >> 1)

	// A canary that must survive, observed alongside the error value.
	canary, err := NewMemoryEnclave([]byte("canary-key-material"))
	if err != nil {
		t.Fatalf("could not allocate the canary enclave: %v", err)
	}
	defer canary.Destroy()

	for _, tc := range []struct {
		name string
		n    int
	}{
		{"platform maximum", maxIntV},
		{"data region rounds, mapping does not", maxIntV - int(pageSize)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Unadmitted path: its own size check is the only guard.
			e, err := NewMemoryEnclaveSized(tc.n)
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("NewMemoryEnclaveSized(%d) = %v, want ErrInvalidSize", tc.n, err)
			}
			if errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Error("the request reached memguard; the size check did not run first")
			}
			if e != nil {
				t.Error("a non-nil enclave was returned")
				e.Destroy()
			}

			// Admitted path, with a budget admission cannot refuse on.
			a, err := NewAllocator(maxInt)
			if err != nil {
				t.Fatalf("NewAllocator: %v", err)
			}
			e, err = a.NewSized(tc.n)
			if !errors.Is(err, ErrInvalidSize) {
				t.Errorf("NewSized(%d) = %v, want ErrInvalidSize", tc.n, err)
			}
			if errors.Is(err, ErrLockedMemoryUnavailable) {
				t.Error("the request reached memguard; admission failed open")
			}
			if e != nil {
				t.Error("a non-nil enclave was returned")
				e.Destroy()
			}
			if got := a.InUse(); got != 0 {
				t.Errorf("InUse = %d after the refusal, want 0", got)
			}

			if !canary.IsAlive() {
				t.Fatal("an unrelated enclave died: memguard was entered and purged the process")
			}
		})
	}

	if !holds(canary, []byte("canary-key-material")) {
		t.Error("the canary's material did not survive")
	}
}

// TestAllocator_reserve_DoesNotOverflow pins the two arithmetic guards on
// admission, separately because one request cannot reach both: the page
// rounding (size guard) and the budget predicate, where `used+charge > limit`
// would wrap negative and admit. The budget wrap is reachable only where int is
// 64 bits; on 32-bit the same assertions hold as a plain over-budget refusal.
func TestAllocator_reserve_DoesNotOverflow(t *testing.T) {
	// Size guard: MaxInt64 has no representable mapping, so it is
	// ErrInvalidSize before any budget comparison.
	a, err := NewAllocator(math.MaxInt64)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if _, err := a.reserve(1); err != nil {
		t.Fatalf("reserve(1): %v", err)
	}
	if a.InUse() != pageSize {
		t.Fatalf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
	if _, err := a.reserve(math.MaxInt64); !errors.Is(err, ErrInvalidSize) {
		t.Errorf("reserve(MaxInt64) = %v, want ErrInvalidSize", err)
	}
	if got := a.InUse(); got != pageSize {
		t.Errorf("InUse = %d after the refusal, want the unchanged %d", got, pageSize)
	}

	// Budget predicate: widest clears every size guard, and with pages already
	// spoken for it is over budget; on 64-bit used+charge would overflow.
	widest := (maxInt - 2*pageSize) / pageSize * pageSize
	if _, ok := lockedSize(widest); !ok {
		t.Fatalf("lockedSize(%d) refused; the test would never reach the budget predicate", widest)
	}

	w, err := NewAllocator(widest)
	if err != nil {
		t.Fatalf("NewAllocator(widest): %v", err)
	}
	const spokenFor = 4
	for i := 0; i < spokenFor; i++ {
		if _, err := w.reserve(1); err != nil {
			t.Fatalf("reserve(1) #%d: %v", i, err)
		}
	}
	before := w.InUse()
	if before != spokenFor*pageSize {
		t.Fatalf("InUse = %d, want %d", before, spokenFor*pageSize)
	}
	if _, err := w.reserve(widest); !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("reserve(widest) = %v, want ErrBudgetExhausted", err)
	}
	if got := w.InUse(); got != before {
		t.Errorf("InUse = %d after the refusal, want the unchanged %d (the counter wrapped)", got, before)
	}

	// Through NewSized: a failed guard would surface as
	// ErrLockedMemoryUnavailable from the mapping instead of ErrBudgetExhausted.
	small, err := NewAllocator(2 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	e, err := small.NewSized(int(widest))
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Errorf("NewSized(widest) against a two-page budget = %v, want ErrBudgetExhausted", err)
	}
	if errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Error("the request reached memguard; admission failed open")
	}
	if e != nil {
		t.Error("NewSized(widest) returned a non-nil enclave")
		e.Destroy()
	}
	if got := small.InUse(); got != 0 {
		t.Errorf("InUse = %d after the refusal, want 0", got)
	}
}

// TestAllocator_NewSized_DestroyReleasesReservation pins that Destroy returns a
// NewSized reservation exactly once: a full budget admits again after Destroy,
// and a double Destroy does not underflow.
func TestAllocator_NewSized_DestroyReleasesReservation(t *testing.T) {
	a, err := NewAllocator(pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := a.NewSized(16)
	if err != nil {
		t.Fatalf("NewSized (full): %v", err)
	}
	if a.InUse() != pageSize {
		t.Fatalf("InUse = %d, want one page (%d)", a.InUse(), pageSize)
	}
	if _, err := a.NewSized(1); !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("NewSized while full err = %v, want ErrBudgetExhausted", err)
	}

	e.Destroy()
	if a.InUse() != 0 {
		t.Fatalf("InUse = %d after Destroy, want 0 (reservation not released)", a.InUse())
	}
	e.Destroy() // idempotent; must not release twice and underflow
	if a.InUse() != 0 || a.Available() != pageSize {
		t.Fatalf("InUse = %d Available = %d after a double Destroy, want 0 and %d", a.InUse(), a.Available(), pageSize)
	}

	e2, err := a.NewSized(16)
	if err != nil {
		t.Fatalf("NewSized after release: %v (budget was not returned)", err)
	}
	e2.Destroy()
}

// TestAllocator_NewSized_Concurrent runs concurrent fill-verify-destroy cycles
// against a tight budget: InUse never exceeds the limit, each enclave holds its
// own goroutine's material, and the counter returns to zero.
func TestAllocator_NewSized_Concurrent(t *testing.T) {
	// Budget in pages; the admitted counter fails the test if nothing was admitted.
	const (
		capacity = 5
		size     = 40
	)
	limit := capacity * pageSize
	a, err := NewAllocator(limit)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var admitted atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			want := bytes.Repeat([]byte{byte(g)}, size)
			for i := 0; i < 200; i++ {
				e, err := a.NewSized(size)
				if err != nil {
					if !errors.Is(err, ErrBudgetExhausted) {
						t.Errorf("unexpected NewSized err: %v", err)
					}
					continue
				}
				admitted.Add(1)
				if u := a.InUse(); u > limit {
					t.Errorf("InUse = %d exceeded limit %d", u, limit)
				}
				if err := e.WithBytes(func(b []byte) error {
					copy(b, want)
					return nil
				}); err != nil {
					t.Errorf("fill: %v", err)
				}
				if !holds(e, want) {
					t.Error("an enclave did not hold what this goroutine generated into it")
				}
				e.Destroy()
			}
		}(g)
	}
	wg.Wait()

	if admitted.Load() == 0 {
		t.Fatal("every allocation was refused; the budget admits nothing and this test asserted nothing")
	}
	if a.InUse() != 0 {
		t.Errorf("InUse = %d after all destroys, want 0", a.InUse())
	}
	if a.Available() != limit {
		t.Errorf("Available = %d, want the full %d", a.Available(), limit)
	}
}

// TestMemoryEnclave_FreezeProtectsAfterTheFill pins that fill-then-Freeze
// leaves the region read-only (m.mutable false) and every accessor still
// working. The fault itself is exercised by
// TestMemoryEnclave_FrozenSizedPagesFault. An unfrozen sized enclave is the
// control.
func TestMemoryEnclave_FreezeProtectsAfterTheFill(t *testing.T) {
	material := bytes.Repeat([]byte{0xA5}, 32)

	control, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer control.Destroy()
	if !control.m.mutable {
		t.Fatal("a fresh sized enclave is already read-only; the fill would fault and this test would be vacuous")
	}

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer e.Destroy()

	if err := e.WithBytes(func(b []byte) error {
		copy(b, material)
		return nil
	}); err != nil {
		t.Fatalf("filling the enclave: %v", err)
	}

	if err := e.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	if e.m.mutable {
		t.Error("the enclave is still writable after Freeze; a stray write would corrupt it silently")
	}

	// Freezing changes protection only; every accessor keeps working.
	if !holds(e, material) {
		t.Error("the material did not survive the freeze")
	}
	if got := e.Size(); got != len(material) {
		t.Errorf("Size() = %d, want %d", got, len(material))
	}
	if !e.IsAlive() {
		t.Error("IsAlive() = false after Freeze")
	}
	if err := e.WithBytes(func(b []byte) error {
		if !bytes.Equal(b, material) {
			t.Error("a borrow of a frozen enclave read the wrong bytes")
		}
		return nil
	}); err != nil {
		t.Errorf("borrowing a frozen enclave: %v", err)
	}
}

// TestMemoryEnclave_FreezeIsIdempotent pins that Freeze is a nil no-op on an
// enclave already frozen, whether by an earlier Freeze or by NewMemoryEnclave
// or NewMemoryEnclaveCopy, which both return read-only enclaves.
func TestMemoryEnclave_FreezeIsIdempotent(t *testing.T) {
	sized, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer sized.Destroy()

	if err := sized.Freeze(); err != nil {
		t.Fatalf("first Freeze: %v", err)
	}
	if err := sized.Freeze(); err != nil {
		t.Errorf("second Freeze: %v, want nil", err)
	}
	if sized.m.mutable {
		t.Error("the second Freeze left the enclave writable")
	}

	// A move-constructed enclave arrives frozen.
	moved, err := NewMemoryEnclave([]byte("private-key-material"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	defer moved.Destroy()
	if moved.m.mutable {
		t.Fatal("a move-constructed enclave is writable; the case under test does not exist")
	}
	if err := moved.Freeze(); err != nil {
		t.Errorf("Freeze on an already-frozen enclave: %v, want nil", err)
	}
	if !holds(moved, []byte("private-key-material")) {
		t.Error("the material did not survive a redundant freeze")
	}

	// So does a copy-constructed one.
	src := []byte("material the caller keeps")
	copied, err := NewMemoryEnclaveCopy(src)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}
	defer copied.Destroy()
	if copied.m.mutable {
		t.Fatal("a copy-constructed enclave is writable; the case under test does not exist")
	}
	if err := copied.Freeze(); err != nil {
		t.Errorf("Freeze on a copy-constructed enclave: %v, want nil", err)
	}
	if !holds(copied, src) {
		t.Error("the material did not survive a redundant freeze on a copy-constructed enclave")
	}
	if !bytes.Equal(src, []byte("material the caller keeps")) {
		t.Error("freezing a copy-constructed enclave touched the caller's source buffer")
	}
}

// TestMemoryEnclave_FreezeReportsDestroyed pins that Freeze on a nil or
// destroyed enclave returns ErrEnclaveDestroyed, with a live control.
func TestMemoryEnclave_FreezeReportsDestroyed(t *testing.T) {
	var nilEnclave *MemoryEnclave
	if err := nilEnclave.Freeze(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("(nil).Freeze() = %v, want ErrEnclaveDestroyed", err)
	}

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}

	// The control: the same enclave while alive.
	if err := e.Freeze(); err != nil {
		t.Fatalf("Freeze on a live enclave: %v, want nil", err)
	}

	e.Destroy()
	if err := e.Freeze(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Freeze on a destroyed enclave = %v, want ErrEnclaveDestroyed", err)
	}
}

// TestMemoryEnclave_FreezeRefusesAWipedMapping pins that Freeze on a mapping
// kept after its wipe (release refused, Destroy retryable) returns
// ErrEnclaveDestroyed and leaves the region writable, so the retried release
// needs no extra mprotect.
func TestMemoryEnclave_FreezeRefusesAWipedMapping(t *testing.T) {
	// Unexported constructor: wipeAndVerify is driven directly, so nothing
	// deregisters, and a ledger entry would leak into every WipeAll test.
	e, err := unpublishedSized(32)
	if err != nil {
		t.Fatalf("newMemoryEnclaveSized: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	// The control, while there is still material.
	if err := e.WithBytes(func(b []byte) error {
		copy(b, bytes.Repeat([]byte{0x11}, len(b)))
		return nil
	}); err != nil {
		t.Fatalf("filling the enclave: %v", err)
	}
	if err := e.Freeze(); err != nil {
		t.Fatalf("Freeze on a live enclave: %v, want nil", err)
	}

	// wipeAndVerify alone produces the state a refused release leaves: material
	// gone, pages still held.
	if err := e.m.wipeAndVerify(); err != nil {
		t.Fatalf("wipeAndVerify: %v", err)
	}
	if !e.m.wiped {
		t.Fatal("wipeAndVerify did not record the wipe; this test cannot assert what it claims")
	}
	if e.m.memory == nil {
		t.Fatal("the mapping was released; this test needs the KEPT-mapping case")
	}

	if err := e.Freeze(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Freeze on a wiped-but-kept mapping = %v, want ErrEnclaveDestroyed", err)
	}
	// The kept mapping stays writable so the retry needs no further mprotect.
	if !e.m.mutable {
		t.Error("Freeze re-protected a wiped mapping read-only; the retried release now needs " +
			"an extra mprotect on the path that is already being refused")
	}
	if e.IsAlive() {
		t.Error("IsAlive reports true for an enclave whose material is gone")
	}
}

// TestMemoryEnclave_FreezeWaitsForBorrows pins that Freeze takes the write
// lock: it does not return while a borrow (a fill in progress) is in flight, and
// does return once the borrow ends. Under a read lock the mprotect could land
// mid-fill and fault the filling goroutine.
func TestMemoryEnclave_FreezeWaitsForBorrows(t *testing.T) {
	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer e.Destroy()

	entered := make(chan struct{})
	release := make(chan struct{})
	borrowReturned := make(chan struct{})
	var borrowDone atomic.Bool

	go func() {
		defer close(borrowReturned)
		if err := e.WithBytes(func(b []byte) error {
			close(entered)
			<-release
			borrowDone.Store(true)
			return nil
		}); err != nil {
			t.Errorf("borrow: %v", err)
		}
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the borrow never started")
	}

	frozen := make(chan error, 1)
	go func() { frozen <- e.Freeze() }()

	select {
	case err := <-frozen:
		close(release)
		t.Fatalf("Freeze returned (%v) while a borrow was still in flight; it is not taking the write lock, "+
			"so the mprotect can land mid-fill", err)
	case <-time.After(100 * time.Millisecond):
		// Still waiting, as required.
	}

	close(release)
	select {
	case err := <-frozen:
		if err != nil {
			t.Errorf("Freeze after the borrow returned: %v", err)
		}
		if !borrowDone.Load() {
			t.Error("Freeze returned without the borrow having completed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Freeze never returned after the borrow released the lock")
	}

	<-borrowReturned
	if e.m.mutable {
		t.Error("the enclave is still writable after Freeze")
	}
}

// TestMemoryEnclave_FreezeFailureLeavesTheEnclaveUsable pins that a refused
// mprotect returns ErrLockedMemoryUnavailable and leaves the enclave alive,
// writable and holding its material (unlike a constructor, which releases), and
// that a retry succeeds. The refusal is injected through the protectMemory seam.
func TestMemoryEnclave_FreezeFailureLeavesTheEnclaveUsable(t *testing.T) {
	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer e.Destroy()

	material := bytes.Repeat([]byte{0x5A}, 32)
	if err := e.WithBytes(func(b []byte) error {
		copy(b, material)
		return nil
	}); err != nil {
		t.Fatalf("filling the enclave: %v", err)
	}

	lift := denyProtect(t)
	err = e.Freeze()
	lift()

	if err == nil {
		t.Fatal("Freeze reported success on a region the kernel cannot protect")
	}
	if !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Errorf("err = %v, want ErrLockedMemoryUnavailable", err)
	}

	if !e.IsAlive() {
		t.Error("a refused Freeze destroyed the enclave")
	}
	if !e.m.mutable {
		t.Error("a refused Freeze recorded the enclave as frozen; the next Destroy would melt pages that were never protected")
	}
	if !holds(e, material) {
		t.Error("the material did not survive a refused Freeze")
	}
	// Still writable.
	if err := e.WithBytes(func(b []byte) error {
		b[0] ^= 0xFF
		return nil
	}); err != nil {
		t.Errorf("writing to an enclave whose Freeze was refused: %v", err)
	}
	material[0] ^= 0xFF
	if !holds(e, material) {
		t.Error("the write after a refused Freeze did not take")
	}

	// A retry succeeds.
	if err := e.Freeze(); err != nil {
		t.Errorf("Freeze after a transient refusal: %v", err)
	}
	if e.m.mutable {
		t.Error("the retried Freeze did not take")
	}
}

// TestWipeAll_ReclaimsAFrozenEnclave pins that the sweep makes a frozen region
// writable, wipes and releases it, leaving nothing behind.
func TestWipeAll_ReclaimsAFrozenEnclave(t *testing.T) {
	requireCleanLedger(t)

	e, err := NewMemoryEnclaveSized(64)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer e.Destroy() // a no-op once the sweep has taken it; here for the failure paths

	if err := e.WithBytes(func(b []byte) error {
		copy(b, bytes.Repeat([]byte{0x3C}, len(b)))
		return nil
	}); err != nil {
		t.Fatalf("filling the enclave: %v", err)
	}
	if err := e.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}

	remaining, err := WipeAll(context.Background())
	if err != nil {
		t.Errorf("WipeAll: %v", err)
	}
	if remaining != 0 {
		t.Errorf("WipeAll left %d enclaves holding locked memory, want 0", remaining)
	}
	if e.IsAlive() {
		t.Error("the frozen enclave survived the sweep")
	}
}

// TestAllocator_FreezeKeepsTheReservation pins that Freeze does not move the
// Allocator charge and that Destroy of a frozen enclave returns it.
func TestAllocator_FreezeKeepsTheReservation(t *testing.T) {
	a, err := NewAllocator(4 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := a.NewSized(32)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}

	before := a.InUse()
	if before == 0 {
		t.Fatal("nothing was reserved; the test would be vacuous")
	}

	if err := e.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	if after := a.InUse(); after != before {
		t.Errorf("InUse() = %d after Freeze, want %d — freezing changed the reservation", after, before)
	}

	e.Destroy()
	if after := a.InUse(); after != 0 {
		t.Errorf("InUse() = %d after destroying a frozen enclave, want 0", after)
	}
}

// The borrow benchmarks measure what a reader pays for an enclave's read-lock
// bracket. Compare them with benchstat before and after any change to
// withLocked, Size, IsAlive or borrow bookkeeping. The callback is empty so the
// bracket dominates.

// newBenchEnclave returns a small frozen enclave, destroyed at cleanup.
func newBenchEnclave(b *testing.B) *MemoryEnclave {
	b.Helper()
	e, err := NewMemoryEnclaveCopy(make([]byte, 32))
	if err != nil {
		b.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}
	b.Cleanup(func() {
		if err := e.Destroy(); err != nil {
			b.Errorf("Destroy: %v", err)
		}
	})
	return e
}

// noopBorrow is package-level so taking it allocates no closure.
func noopBorrow([]byte) error { return nil }

// BenchmarkBorrowSerial is one goroutine borrowing one enclave: the
// uncontended cost of the read-lock bracket.
func BenchmarkBorrowSerial(b *testing.B) {
	e := newBenchEnclave(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := e.WithBytes(noopBorrow); err != nil {
			b.Fatalf("WithBytes: %v", err)
		}
	}
}

// BenchmarkBorrowParallelShared is GOMAXPROCS goroutines borrowing one enclave,
// where any write added to the bracket contends on the lock's cache line.
func BenchmarkBorrowParallelShared(b *testing.B) {
	e := newBenchEnclave(b)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if err := e.WithBytes(noopBorrow); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkBorrowParallelDistinct is GOMAXPROCS goroutines each borrowing its
// own enclave, exposing any package-level state a borrow writes.
func BenchmarkBorrowParallelDistinct(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		e, err := NewMemoryEnclaveCopy(make([]byte, 32))
		if err != nil {
			b.Error(err)
			return
		}
		defer func() {
			if err := e.Destroy(); err != nil {
				b.Error(err)
			}
		}()
		for pb.Next() {
			if err := e.WithBytes(noopBorrow); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

// BenchmarkIsAliveParallel polls IsAlive on one enclave from every core.
func BenchmarkIsAliveParallel(b *testing.B) {
	e := newBenchEnclave(b)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !e.IsAlive() {
				b.Error("IsAlive reported a live enclave destroyed")
				return
			}
		}
	})
}

// TestRelease_RetryReturnsTheReservationUnderStrictUnlock pins, through Destroy
// and WipeAll, that under VirtualUnlock semantics an enclave whose munmap was
// refused once is released by a retry and its Allocator charge returned.
func TestRelease_RetryReturnsTheReservationUnderStrictUnlock(t *testing.T) {
	for _, tc := range []struct {
		name  string
		retry func(t *testing.T, e *MemoryEnclave, wantHeld bool)
	}{
		{"Destroy", func(t *testing.T, e *MemoryEnclave, wantHeld bool) {
			err := e.Destroy()
			if got := pagesHeld(err); got != wantHeld {
				t.Fatalf("Destroy = %v, pagesHeld %v, want %v", err, got, wantHeld)
			}
			if !wantHeld && err != nil {
				t.Fatalf("Destroy = %v, want nil", err)
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

			// Registered first, the sweep runs after the seams are restored.
			t.Cleanup(func() { _, _ = WipeAll(context.Background()) })
			installStrictUnlock(t)
			prevUnmap := swapSeam(t, &unmapMemory, func([]byte) error { return errors.New("munmap: cannot allocate memory") })

			tc.retry(t, e, true)
			if used := a.InUse(); used != pageSize {
				t.Errorf("InUse = %d with the pages still mapped, want %d", used, pageSize)
			}

			unmapMemory = prevUnmap
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

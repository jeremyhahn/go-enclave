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
)

func TestNewMemoryEnclave_HoldsMaterial(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("private-key-material"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	defer e.Destroy()

	got, err := e.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Compared in place: the view aliases the locked pages, and neither a
	// string conversion nor a %q of it may carry the material onto the heap or
	// into the test log (#90; security-review.md §6).
	if !bytes.Equal(got, []byte("private-key-material")) {
		t.Errorf("Open returned a %d-byte view that does not hold the material it was built from", len(got))
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

// TestNewMemoryEnclaveCopy_LeavesTheSourceIntact is the load-bearing test for
// the copy constructor, and it has two halves on purpose.
//
// The half under test is that the source SURVIVES. On its own it would also
// pass against a build in which NewMemoryEnclave had stopped wiping — a silent
// security regression in the constructor everything else defaults to, and the
// live risk here specifically, because the two constructors now share one body
// and the wipe is the only thing separating them. So the companion half pushes
// identical bytes through NewMemoryEnclave and requires them gone. Neither half
// alone shows the two constructors DIFFER; together they do.
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

// TestNewMemoryEnclaveCopy_IsIndependentOfTheSource covers the other way
// "leaves the source intact" could be satisfied and still be wrong: an enclave
// that ALIASED the caller's bytes would pass the wipe assertion above while
// protecting nothing, and would then be corrupted — or unmapped — by whatever
// the caller does with its own slice next.
//
// So both directions are exercised. A write through the source must not reach
// the material, and wiping the source afterwards — which is exactly what a
// careful caller does once it is done — must leave the enclave holding what it
// was given.
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

// TestNewMemoryEnclaveCopy_PagesAreFrozen pins the writability decision the
// constructor documents, cheaply and in-process.
//
// The real oracle for this property is a fault, not an assertion — a write
// through frozen pages kills the process, so the end-to-end version lives in a
// subprocess (TestMemoryEnclave_CopyConstructedPagesAreReadOnly). This one
// reads the protection state directly so that a build that forgot to freeze
// fails with a named error rather than a SIGSEGV in a child, and it carries a
// sized enclave as its control: without it, an assertion that "mutable is
// false" would pass just as happily against a field that is never true.
func TestNewMemoryEnclaveCopy_PagesAreFrozen(t *testing.T) {
	e, err := NewMemoryEnclaveCopy([]byte("frozen-after-copy"))
	if err != nil {
		t.Fatalf("NewMemoryEnclaveCopy: %v", err)
	}
	defer e.Destroy()

	if e.m.mutable {
		t.Error("a copy-constructed enclave is writable; a stray write would corrupt it silently instead of faulting")
	}

	// The control: the field can say "yes", and a sized enclave must, or the
	// generate-in-place path would fault on its own fill.
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

// TestNewMemoryEnclaveCopy_IsPublishedToTheLedger asserts the new constructor
// registers what it hands out. Nothing in ordinary use reveals the omission:
// the enclave works, and the only symptom is that a shutdown sweep quietly
// walks past it, leaving the material resident on exit — the failure mode
// WipeAll was added for in v0.4.0-alpha.
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

func TestNewMemoryEnclaveFromString(t *testing.T) {
	e, err := NewMemoryEnclaveFromString("AKIAIOSFODNN7EXAMPLE")
	if err != nil {
		t.Fatalf("NewMemoryEnclaveFromString: %v", err)
	}
	defer e.Destroy()

	// OpenString is the API under test here — the string boundary it exists
	// for — so its result is judged, never printed (#90).
	got, err := e.OpenString()
	if err != nil {
		t.Fatalf("OpenString: %v", err)
	}
	if got != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("OpenString returned a %d-byte string that is not the material", len(got))
	}

	if _, err := NewMemoryEnclaveFromString(""); !errors.Is(err, ErrEmptyEnclave) {
		t.Errorf("empty string err = %v, want ErrEmptyEnclave", err)
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
	if _, err := e.Open(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open err = %v, want ErrEnclaveDestroyed", err)
	}
	if _, err := e.OpenString(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("OpenString err = %v, want ErrEnclaveDestroyed", err)
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
	if _, err := e.Open(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open err = %v, want ErrEnclaveDestroyed", err)
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

func TestWipe(t *testing.T) {
	b := []byte("scrub")
	Wipe(b)
	for i, c := range b {
		if c != 0 {
			t.Errorf("byte %d = %d, want 0", i, c)
		}
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
			// Read through the scoped accessor, NOT Open: Open hands back a
			// slice that outlives the lock, so dereferencing it here would
			// race the Destroy below against unmapped pages — the very fault
			// this test is supposed to rule out. Either the material or
			// ErrEnclaveDestroyed is correct; a race or a fault is not.
			if s, err := e.OpenString(); err == nil && s != "concurrent" {
				t.Errorf("OpenString returned a %d-byte string that is not the material", len(s))
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

// TestMemoryEnclave_DestroyWaitsForInFlightReader asserts the lifetime
// discipline the concurrency contract promises: Destroy blocks until an
// in-flight scoped borrow has returned, instead of wiping and unmapping the
// pages the borrower is still reading. An atomic swap of the buffer handle
// would satisfy IsAlive and still leave the reader on freed memory, so the
// property under test is the ordering, not the flag.
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
			// Ordered from INSIDE the borrow, while the read lock is still
			// held. Placed after WithBytes returns — where it used to be — it
			// is ordered against nothing: the lock drops on return, so Destroy
			// is free to take the write lock, finish, and increment first,
			// leaving this store unexecuted when the assertion below reads it
			// (#27; seen as "reader exited at 0 and Destroy at 1"). Here, the
			// increment happens-before the lock is released, which
			// happens-before Destroy can acquire it — so the ordering the
			// assertion checks is the lock discipline itself rather than
			// goroutine scheduling.
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

	// Destroy must not complete while the borrow is outstanding. The reader is
	// parked on release, so a Destroy that returns here returned while another
	// goroutine held a live view of the locked pages.
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
				_, _ = e.OpenString()
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

// TestLockedMemoryError covers the typed error's contract: callers match the
// ErrLockedMemoryUnavailable sentinel and never the struct, the memguard
// diagnostic survives for an operator, and errors.As reaches a cause that
// happens to be an error.
func TestLockedMemoryError(t *testing.T) {
	t.Run("matches the sentinel with no cause", func(t *testing.T) {
		err := error(&LockedMemoryError{})
		if !errors.Is(err, ErrLockedMemoryUnavailable) {
			t.Error("errors.Is did not match ErrLockedMemoryUnavailable")
		}
		if err.Error() != ErrLockedMemoryUnavailable.Error() {
			t.Errorf("Error() = %q, want the bare sentinel text", err.Error())
		}
	})

	t.Run("matches the sentinel and keeps the cause", func(t *testing.T) {
		err := error(&LockedMemoryError{Cause: "could not acquire lock, limit reached?"})
		if !errors.Is(err, ErrLockedMemoryUnavailable) {
			t.Error("errors.Is did not match ErrLockedMemoryUnavailable")
		}
		if !strings.Contains(err.Error(), "limit reached?") {
			t.Errorf("Error() = %q, want the memguard diagnostic retained", err.Error())
		}
	})

	t.Run("does not match unrelated sentinels", func(t *testing.T) {
		if errors.Is(&LockedMemoryError{}, ErrEnclaveDestroyed) {
			t.Error("matched ErrEnclaveDestroyed")
		}
	})

	t.Run("unwraps an error cause", func(t *testing.T) {
		cause := errors.New("mmap: cannot allocate memory")
		err := error(&LockedMemoryError{Cause: cause})
		if !errors.Is(err, cause) {
			t.Error("errors.Is did not reach the wrapped cause")
		}
		if got := errors.Unwrap(err); got != cause {
			t.Errorf("Unwrap() = %v, want the cause", got)
		}
	})

	t.Run("unwraps to nil for a non-error cause", func(t *testing.T) {
		if got := errors.Unwrap(error(&LockedMemoryError{Cause: "a string panic"})); got != nil {
			t.Errorf("Unwrap() = %v, want nil", got)
		}
	})
}

// TestEqualToSeparatesMismatchFromDestroyed pins that a mismatch is
// (false, nil) and a missing enclave is (false, ErrEnclaveDestroyed): an
// inverted test must never read a destroyed enclave as a definite mismatch.
func TestEqualToSeparatesMismatchFromDestroyed(t *testing.T) {
	const material = "the real material"

	t.Run("match", func(t *testing.T) {
		e, err := NewMemoryEnclaveFromString(material)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveFromString: %v", err)
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
		e, err := NewMemoryEnclaveFromString(material)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveFromString: %v", err)
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
		e, err := NewMemoryEnclaveFromString(material)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveFromString: %v", err)
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

// allZero reports whether every byte of b is zero. Tests judge enclave
// contents with it IN PLACE — inside a borrow or a seam — rather than copying
// them out to compare, because a test may not move material out of locked
// memory to assert on it (#90; security-review.md §6).
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// generateInto fills the sized enclave e from the CSPRNG through a borrow and
// records what was generated in a second locked enclave — the yardstick — from
// inside that SAME borrow. The material therefore never exists outside locked
// memory, and a later comparison against the yardstick (sameMaterial) says
// whether e still holds exactly what was generated into it. The caller owns
// the yardstick and must Destroy it.
func generateInto(t *testing.T, e *MemoryEnclave) *MemoryEnclave {
	t.Helper()
	yardstick, err := NewMemoryEnclaveSized(e.Size())
	if err != nil {
		t.Fatalf("allocating the yardstick enclave: %v", err)
	}
	var zero bool
	if err := e.WithBytes(func(key []byte) error {
		// Exactly the shape the doc comment prescribes: the CSPRNG writes
		// straight into the locked pages, never into an intermediate slice.
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return err
		}
		zero = allZero(key)
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
	// Re-read BOTH through fresh borrows. The fill went through WithBytes on
	// each, so if a borrow ever handed out a detached copy instead of the
	// locked pages, both would still read as zero and every comparison below
	// would accept zero against zero. A reference must not share the defect
	// it is the yardstick for: persistence is checked here, independently.
	var storedZero, yardstickZero bool
	if err := e.WithBytes(func(b []byte) error { storedZero = allZero(b); return nil }); err != nil {
		_ = yardstick.Destroy()
		t.Fatalf("re-reading the filled enclave: %v", err)
	}
	if err := yardstick.WithBytes(func(b []byte) error { yardstickZero = allZero(b); return nil }); err != nil {
		_ = yardstick.Destroy()
		t.Fatalf("re-reading the yardstick: %v", err)
	}
	if storedZero || yardstickZero {
		_ = yardstick.Destroy()
		t.Fatalf("the fill did not persist (enclave all-zero %t, yardstick all-zero %t): a borrow wrote to something other than the locked pages", storedZero, yardstickZero)
	}
	return yardstick
}

// sameMaterial reports whether a and b hold identical material. It compares
// through nested borrows, so neither side is ever copied out of locked memory,
// and it goes through a's EqualTo — the locked, constant-time accessor — so
// that accessor is exercised against the real storage too.
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

// TestDestroy_ReleaseFailureIsReturnedNotPanicked is the regression for #83's
// Destroy finding: a plain release failure — the munlock or munmap after a
// successful wipe refused, ENOMEM at vm.max_map_count being the realistic one —
// PANICKED, because what is now Destroy (DestroyErr until #88) panicked on every
// error that was not ErrReleasedWithoutWipe. The documentation on both methods
// and the package said only detected corruption panics, and a resource refusal is the
// opposite of a state the caller cannot reason about: the material is gone, the
// pages are held for a retry, and a retry is exactly what the caller should do.
//
// Asserts the whole retained-for-retry contract, not just the absence of the
// panic: the error is returned and typed, the mapping is kept, the enclave reads
// destroyed, it stays on the ledger for WipeAll, the Allocator keeps the charge
// for the pages the kernel still holds — and a retry once the refusal lifts
// completes the release and returns all of it.
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
	prev := unlockMemory
	t.Cleanup(func() {
		unlockMemory = prev
		if e.m != nil {
			_ = e.Destroy()
		}
	})
	unlockMemory = func([]byte) error { return denied }

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

	// A retry while the refusal persists reports it again, and still does not
	// panic: the report is a resource condition, whichever attempt meets it.
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

// TestDestroy_CorruptionSurvivesAFailedRelease: a corrupted canary whose
// release is also refused returns an error matching both ErrEnclaveCorrupted
// and ErrLockedMemoryUnavailable, keeping the mapping and the charge; the retry
// that releases the pages reports the corruption AGAIN, because the first
// attempt's wipe zeroed the bytes a second verification would compare.
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
	// An underflow through a retained slice. A sized enclave is writable, so
	// this is a store rather than a fault.
	e.m.canary[len(e.m.canary)-1] ^= 0xFF

	denied := errors.New("munmap: cannot allocate memory")
	prev := unmapMemory
	t.Cleanup(func() {
		unmapMemory = prev
		if e.m != nil {
			_ = e.Destroy()
		}
	})
	// VirtualUnlock semantics: the first attempt's munlock succeeds, so a retry
	// that unlocks again is refused on Windows before it reaches the munmap.
	installStrictUnlock(t)
	unmapMemory = func([]byte) error { return denied }

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
		clear(destroyedCorrupt)
		registryMu.Unlock()
	})
}

// TestNewMemoryEnclaveSized_ZeroedAndSized covers the two properties the
// constructor's name promises: the enclave is exactly n bytes and every one of
// them is zero. A caller that generates only part of the region — a short read,
// a derivation that fills a prefix — must not find another allocation's remnant
// in the tail.
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

// TestNewMemoryEnclaveSized_FillsInPlace is the generate-in-place property, and
// the reason this constructor exists.
//
// It is asserted as ALIASING, not as a happy return: material written through
// one borrow must be visible through the next. A borrow that handed out a copy
// — or a buffer memguard had frozen read-only, as it freezes every enclave
// built from existing material — would leave the second borrow reading zeroes,
// so both mutations turn this red. Together with the mlock proof in
// TestNewMemoryEnclaveSized_MemoryIsLocked (Linux), that establishes the
// property the issue asks for: the bytes the generator produces land in locked
// memory and nowhere else. No third assertion is available for "no heap copy",
// because the API takes no []byte at all — there is no other place for a copy
// to be.
func TestNewMemoryEnclaveSized_FillsInPlace(t *testing.T) {
	const n = 32

	e, err := NewMemoryEnclaveSized(n)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer e.Destroy()

	// The yardstick is derived from the fill itself and kept independent of
	// the enclave: what the generator produced, recorded as it was produced —
	// into a second LOCKED enclave, from inside the filling borrow. An
	// ordinary []byte yardstick would be the very heap copy of generated
	// material this constructor exists to prevent (#90).
	want := generateInto(t, e)
	defer want.Destroy()

	// A SEPARATE borrow. If the first one wrote to a copy, this reads zeroes.
	// Compared against the yardstick through nested borrows, in place.
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

// TestNewMemoryEnclaveSized_RejectsNonPositive asserts the size guard, and that
// it decides BEFORE memguard is entered.
//
// The error type is what proves the ordering. memguard's own answer to a size
// below one is a dead buffer rather than a panic, so lockedEnclave would report
// it as ErrLockedMemoryUnavailable; getting ErrInvalidSize instead can only mean
// the guard ran first. Delete the guard and this test fails on the sentinel,
// not merely on a message.
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

// TestNewMemoryEnclaveSized_Lifecycle covers the destroyed contract for an
// enclave that was filled rather than moved into: the material is gone, and
// every accessor reports ErrEnclaveDestroyed instead of touching unmapped pages.
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
	if _, err := e.Open(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Open err = %v, want ErrEnclaveDestroyed", err)
	}
	if holds(e, material) {
		t.Error("EqualTo = true on a destroyed enclave")
	}
}

// TestNewMemoryEnclaveSized_ConcurrentBorrowsAndDestroy runs the scoped-borrow
// paths of a filled sized enclave against a concurrent Destroy, matching the
// coverage the move-in constructor already has. Under -race this catches an
// access that escapes the enclave's lock; without it, a read of a destroyed
// buffer. The fill completes before any of it starts, which is the discipline
// the constructor documents.
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
					// Either the material or a destroyed enclave is correct; a
					// half-visible region is not.
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

// TestAllocator_NewSized_RefusesOverBudget asserts admission gates the sized
// constructor the same way it gates New: over-budget is refused with
// ErrBudgetExhausted, no enclave comes back, and the counter is untouched.
//
// That the refusal happens before memguard is a separate claim, proved under an
// injected lock fault in TestAllocator_NewSized_RefusalNeverEntersMemguard
// (Linux) — a typed error alone cannot show it, since ErrLockedMemoryUnavailable
// is typed too and would mean the purge already ran.
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
	// Locked bytes throughout: 16 bytes of material costs a page, and the page
	// already taken is what leaves no room.
	if be.Requested != pageSize || be.Limit != pageSize || be.InUse != pageSize {
		t.Errorf("BudgetError = %+v, want Requested=InUse=Limit=%d", be, pageSize)
	}
}

// TestAllocator_NewSized_RejectsNonPositive asserts the size guard runs ahead of
// admission as well as ahead of memguard: an impossible size is neither charged
// to the budget nor reported as a budget refusal.
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

// TestAllocator_reserve_RefusesNonPositive asserts the gate's counter invariant
// directly, because the public surface cannot see it.
//
// NewSized's own failure path returns whatever it reserved, so a bad reservation
// of -1 bytes is charged and refunded within the one call and InUse reads 0
// either way — a test that only watched NewSized would pass with the check
// deleted. What a concurrent caller would see is the window in between: a
// counter below zero means a budget larger than the limit, and any allocation
// admitted during that window overshoots. Asserting on reserve is the only place
// that window is observable, so the check lives here and is tested here.
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

	// The gate still admits a legitimate reservation afterwards, and charges it
	// the page it will actually cost rather than the 64 bytes asked for.
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

// TestLockedSize pins the accounting unit itself: an enclave costs its size
// rounded UP to a whole page, so everything under a page costs a page.
//
// The exported helper exists because a caller cannot size a budget without it
// — the change this test guards is what makes Limit comparable to
// RLIMIT_MEMLOCK, and a hundred 32-byte credentials need a hundred pages of
// budget, not 3200 bytes.
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

	// Not a size any enclave can have: no rounding is defined, so no cost is
	// reported.
	for _, n := range []int{0, -1, -4096} {
		if got := LockedSize(n); got != 0 {
			t.Errorf("LockedSize(%d) = %d, want 0", n, got)
		}
	}

	// The platform maximum is refused on every platform, and after Codex round
	// 2 on PR #8 it is refused for a second reason as well: even where the data
	// region rounds representably, memguard's mapping is that region PLUS two
	// guard pages, laid out in int arithmetic. So the largest constructible
	// enclave stops short of the platform maximum by those guard pages, and
	// anything past it reports 0 — "not a size any enclave can have".
	//
	// Round 1 of that review argued the return type had to be int64 because a
	// 32-bit platform could produce a locked size above MaxInt32. That reason is
	// now GONE: the guard-page ceiling keeps every valid answer inside int on
	// both word sizes. int64 stays because it matches NewAllocator's budget, and
	// this comment records that the original justification did not survive.
	maxIntV := int(^uint(0) >> 1)
	if got := LockedSize(maxIntV); got != 0 {
		t.Errorf("LockedSize(maxInt) = %d, want 0", got)
	}
	if got := LockedSize(maxIntV - int(pageSize)); got != 0 {
		t.Errorf("LockedSize(maxInt-page) = %d, want 0 (the mapping needs two guard pages too)", got)
	}

	// The boundary itself: the largest size whose data region plus two guard
	// pages still fits, and the first one past it.
	largest := int((maxInt - 2*pageSize) / pageSize * pageSize)
	if got := LockedSize(largest); got != int64(largest) {
		t.Errorf("LockedSize(largest constructible) = %d, want %d", got, largest)
	}
	if got := LockedSize(largest + 1); got != 0 {
		t.Errorf("LockedSize(largest+1) = %d, want 0", got)
	}
}

// TestSizedConstructors_RefuseUnmappableSizes is the regression test for the
// fail-open Codex found in round 2 of PR #8, and it covers BOTH construction
// paths because both reach memguard.
//
// memguard maps roundToPageSize(size) + 2*pageSize in int arithmetic. A size
// whose data region rounds representably can still overflow once the guard pages
// are added; mmap then refuses the nonsense length and core.Panic purges every
// live locked buffer in the process. Measured against v0.2.0-alpha with
// n = MaxInt64-pageSize: admission passed, the request reached memguard, and an
// unrelated canary enclave came back DEAD.
//
// The assertion that matters is the sentinel. ErrInvalidSize means the size was
// refused on this side of the line; ErrLockedMemoryUnavailable would mean the
// request reached memguard and the purge already ran — the failure this exists
// to prevent, wearing a typed error.
//
// The budget is deliberately large enough to admit the rounded charge on both
// word sizes and nothing is pre-reserved, so a refusal here cannot be the budget
// doing the work by accident.
func TestSizedConstructors_RefuseUnmappableSizes(t *testing.T) {
	maxIntV := int(^uint(0) >> 1)

	// A canary that must survive: if the request reaches memguard, the purge
	// destroys it. That is the observable, not just the error value.
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
			// Unadmitted path first: no Allocator stands in front of it at all,
			// so its own size check is the only thing between the caller and a
			// process-wide purge.
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

			// Admitted path, with a budget big enough that admission cannot be
			// what refuses it.
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

// TestAllocator_reserve_DoesNotOverflow covers the two arithmetic guards on the
// admission path. Each is a fail-open into memguard's process-wide purge if it
// wraps, and they are asserted separately because a single request cannot
// exercise both — one is caught before the other is ever consulted.
//
// The SIZE guard is the page rounding. The obvious form, `n+pageSize-1` masked
// down, wraps for a large enough n; it also has to leave room for the two guard
// pages memguard maps alongside the data region (see lockedSize).
//
// The BUDGET guard is the predicate itself, the fail-open Codex found on PR #3:
// `used+charge > limit` performs signed addition, and for a large enough charge
// that addition wraps NEGATIVE, passes the comparison, and admits an allocation
// the budget cannot cover.
//
// One asymmetry, stated rather than hidden: the budget wrap is reachable only
// where int is 64 bits. On a 32-bit platform the largest constructible charge is
// bounded by int, far below the point where adding it to the counter could
// overflow an int64. The assertions below hold on both — as a wrap on 64-bit and
// as an ordinary over-budget refusal on 32-bit — but the mutant that restores
// `used+charge > limit` is only caught on 64-bit, and claiming otherwise would
// be false.
func TestAllocator_reserve_DoesNotOverflow(t *testing.T) {
	// Guard 1 — the size. MaxInt64 has no representable page-rounded cost and
	// no mapping that fits, so it is refused as an impossible SIZE before any
	// budget comparison happens. A larger limit would not help, which is why
	// this is ErrInvalidSize and not ErrBudgetExhausted.
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

	// Guard 2 — the budget predicate. widest is the largest size that clears
	// every size guard, so it reaches the comparison. The budget is exactly its
	// charge and several pages are already spoken for, which makes it over
	// budget on any platform; on 64-bit it is also past the point where
	// used+charge overflows, which is what the restored-predicate mutant needs.
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

	// The public half, through NewSized. Its job is the memguard arm check:
	// with admission intact the request never enters memguard, and with either
	// guard removed it does and comes back with ErrLockedMemoryUnavailable — a
	// different sentinel, from the far side of the purge.
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

// TestAllocator_NewSized_DestroyReleasesReservation is the release-path mutation
// killer for NewSized, asserted on the ALLOCATOR because the enclave itself
// reads back identically whether or not its reservation was returned: fill the
// budget, confirm the next allocation is refused, destroy the holder, and
// confirm an identical allocation now succeeds. Dropping `e.release = …` from
// NewSized leaves the budget consumed forever and fails the final call.
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

// TestAllocator_NewSized_Concurrent runs many concurrent generate-fill-verify-
// destroy cycles against a tight budget. The invariants under -race: InUse never
// exceeds the limit at any observed point, each enclave holds exactly what its
// own goroutine generated into it (so no two fills share storage), and the
// counter returns to exactly zero once everything is destroyed.
func TestAllocator_NewSized_Concurrent(t *testing.T) {
	// Budget in PAGES: each enclave costs one whatever its size, so a budget
	// expressed in the requested bytes would refuse every allocation and leave
	// this test asserting nothing while still reporting green. The admitted
	// counter makes that failure mode loud instead of silent.
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

// TestMemoryEnclave_FreezeProtectsAfterTheFill covers the property Freeze
// exists for, at the level the protection actually lives: m.mutable is the
// package's record of whether the inner region is writable, and it is false only
// when an mprotect to read-only succeeded. The fault that follows from it is
// asserted by execution in TestMemoryEnclave_FrozenSizedPagesFault; this half
// pins that a normal fill-then-freeze reaches that state and that everything
// else about the enclave still works afterwards.
//
// The unfrozen control is not decoration. Without it an implementation that
// reported enclaves frozen from birth would pass — and that implementation
// cannot exist, because a sized enclave has to be filled, so the control is what
// says the assertion measured the freeze rather than the constructor.
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

	// Freezing is a protection change, not a change to the material. Everything
	// a caller does with an enclave has to keep working across it.
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
	// OpenString is the one accessor whose JOB is to materialize a string, so
	// it is called here as the API under test; its result is judged, never
	// printed (#90).
	if s, err := e.OpenString(); err != nil || s != string(material) {
		t.Errorf("OpenString() on a frozen enclave: err = %v, holds the material = %v; want the material "+
			"and no error", err, s == string(material))
	}
}

// TestMemoryEnclave_FreezeIsIdempotent pins the shapes of second freeze that a
// caller can produce without a mistake: freezing an enclave it already froze,
// and freezing one it was handed without knowing which constructor built it.
//
// Both must be a quiet no-op. The alternative — an error on a redundant freeze —
// would force every caller receiving an enclave from elsewhere to track a
// property it cannot observe, and re-issuing the mprotect instead would be a
// syscall that can be refused for no reason at all.
//
// BOTH constructors that bring existing material in are covered, not just the
// one this method was written against. They share newMemoryEnclaveCopy today, so
// asserting only NewMemoryEnclave would be asserting an implementation detail
// that a future split could quietly break — and a caller receiving an enclave
// cannot tell which of the three built it, which is the whole reason this has to
// be a no-op.
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

	// A move-constructed enclave arrives frozen: Freeze must accept it rather
	// than treat the state it wanted as an error.
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

	// And the copy constructor, which arrives frozen for the same reason: its
	// material is complete when it returns.
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

// TestMemoryEnclave_FreezeReportsDestroyed asserts Freeze refuses when there are
// no pages to protect, rather than reporting a success nothing established.
//
// The distinction matters because of what a caller does with the answer: a nil
// return is read as "a stray write faults from here", and a destroyed or nil
// enclave has established no such thing. The live case is asserted alongside so
// an implementation that refused everything could not pass.
func TestMemoryEnclave_FreezeReportsDestroyed(t *testing.T) {
	var nilEnclave *MemoryEnclave
	if err := nilEnclave.Freeze(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("(nil).Freeze() = %v, want ErrEnclaveDestroyed", err)
	}

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}

	// The control: the same call on the same enclave while it is alive.
	if err := e.Freeze(); err != nil {
		t.Fatalf("Freeze on a live enclave: %v, want nil", err)
	}

	e.Destroy()
	if err := e.Freeze(); !errors.Is(err, ErrEnclaveDestroyed) {
		t.Errorf("Freeze on a destroyed enclave = %v, want ErrEnclaveDestroyed", err)
	}
}

// TestMemoryEnclave_FreezeRefusesAWipedMapping is the #40 interaction: a mapping
// KEPT after its material was wiped, because the munlock or munmap that follows
// the wipe was refused and Destroy has to stay retryable.
//
// Every other method on the type calls that state destroyed, and Freeze has to
// give the same answer for reasons past consistency. There is nothing left to
// protect, so a nil return would report fault-on-write established over a region
// of zeroes. And mprotecting it read-only would make the retry MELT pages it has
// already melted — turning a release that needs one refusable syscall into one
// that needs two, on the exact path that is already failing.
//
// The live control is next to it, because a Freeze that refused everything would
// satisfy the refusal on its own.
func TestMemoryEnclave_FreezeRefusesAWipedMapping(t *testing.T) {
	// Unexported: this drives wipeAndVerify directly rather than Destroy, so
	// nothing deregisters, and a ledger entry left behind here is counted by
	// every WipeAll test in the package.
	e, err := newMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("newMemoryEnclaveSized: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	// The control first, while there is still material: the same call on the
	// same enclave has to succeed.
	if err := e.WithBytes(func(b []byte) error {
		copy(b, bytes.Repeat([]byte{0x11}, len(b)))
		return nil
	}); err != nil {
		t.Fatalf("filling the enclave: %v", err)
	}
	if err := e.Freeze(); err != nil {
		t.Fatalf("Freeze on a live enclave: %v, want nil", err)
	}

	// wipeAndVerify is the step that produces the state release() leaves behind
	// when what follows it is refused: material gone, pages still held. Calling
	// it directly reaches that state with no syscall stub at all — the technique
	// #40's own tests use.
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
	// And it must not have re-protected the region on its way out: the kept
	// mapping is left writable by wipeAndVerify precisely so the retry needs no
	// further mprotect.
	if !e.m.mutable {
		t.Error("Freeze re-protected a wiped mapping read-only; the retried release now needs " +
			"an extra mprotect on the path that is already being refused")
	}
	// The enclave agrees with every other method about what it is.
	if e.IsAlive() {
		t.Error("IsAlive reports true for an enclave whose material is gone")
	}
}

// TestMemoryEnclave_FreezeWaitsForBorrows asserts the lock Freeze takes is the
// WRITE lock, which is the difference between bounding a hazard and creating
// one.
//
// A borrow is where the fill happens. If Freeze could run under the read lock it
// would overlap one, and the mprotect would land between two stores of a
// goroutine that is still writing — faulting the filling goroutine on its next
// store. A method whose whole purpose is to convert silent corruption into a
// fault would then be manufacturing the fault itself.
//
// The negative half (Freeze does not return while the borrow is in flight) is
// what catches a read lock; the positive half (it does return once the borrow
// ends, having observed the borrow finished) is what keeps the negative half
// from passing on a Freeze that simply hangs forever. Both waits are bounded, so
// a regression names itself instead of timing out the suite.
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
		// Still waiting, which is the whole point.
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

// TestMemoryEnclave_FreezeFailureLeavesTheEnclaveUsable drives the branch where
// the kernel refuses the mprotect, which is the one place Freeze's contract
// differs from a constructor's.
//
// NewMemoryEnclave releases the mapping when its freeze is refused, because a
// constructor cannot hand back a half-built enclave. Freeze must NOT: the caller
// already owns this enclave, has a Destroy deferred on it, and may well be
// holding the only reference to material it is still able to use. Destroying it
// underneath the caller would turn a failed hardening step into lost key
// material.
//
// So the enclave has to come back exactly as it went in — alive, writable,
// readable — with the failure reported as a typed error. The refusal is
// injected through the protectMemory seam, so the enclave's own slices are
// never touched.
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

	// Everything the caller had, it still has.
	if !e.IsAlive() {
		t.Error("a refused Freeze destroyed the enclave")
	}
	if !e.m.mutable {
		t.Error("a refused Freeze recorded the enclave as frozen; the next Destroy would melt pages that were never protected")
	}
	if !holds(e, material) {
		t.Error("the material did not survive a refused Freeze")
	}
	// Writable, which is what "usable" means for a sized enclave whose fill was
	// not accepted as final.
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

	// And a retry works, which is what makes the failure worth reporting rather
	// than acting on.
	if err := e.Freeze(); err != nil {
		t.Errorf("Freeze after a transient refusal: %v", err)
	}
	if e.m.mutable {
		t.Error("the retried Freeze did not take")
	}
}

// TestWipeAll_ReclaimsAFrozenEnclave pins the interaction between the two
// mechanisms that both act on an enclave's protection.
//
// The sweep's release path has to make a frozen region writable again before it
// can wipe it, and it does that through the same code Destroy uses — but the
// sweep must not panic and must not leave the enclave behind, so a freeze that
// the release path could not undo would show up here as an enclave still holding
// locked memory at exit. That is precisely the failure a shutdown sweep exists to
// prevent, and it would be invisible in any test that only froze and destroyed.
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

// TestAllocator_FreezeKeepsTheReservation asserts freezing is a protection
// change and nothing else. The enclave holds the same locked pages before and
// after, so the budget must not move — and Destroy must still return the
// reservation for an enclave that was frozen, which is the path an admitted
// caller following the documented fill-then-freeze pattern actually takes.
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

// The borrow benchmarks measure the cost a READER pays to hold an enclave's
// lock, which is the path a shutdown sweep has to be able to wait on (#88).
// Making a borrow observable to [WipeAll] must not cost a reader a lock or an
// allocation, and these are what settle what it does cost: run them before and
// after any change to withLocked, Size, IsAlive or the borrow bookkeeping, and
// compare with benchstat. No threshold is wired into CI, for the reason given
// on BenchmarkRefusalSerial.
//
// The callback does nothing on purpose. A real borrow does far more work than
// the bracket around it, and a benchmark whose body dwarfed the bracket would
// report noise as the answer.

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

// noopBorrow is the callback every borrow benchmark runs. A package-level func
// value, so taking it does not allocate a closure per iteration.
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

// BenchmarkBorrowParallelShared is GOMAXPROCS goroutines borrowing ONE enclave.
// Every borrow writes the enclave's lock word, so this is the arm in which a
// read-modify-write added to the bracket shows up at full amplitude: the line
// is already contended, and anything else written on it is contended with it.
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
// OWN enclave. Nothing per-enclave is shared, so the only cross-core cost left
// is whatever package-level state a borrow touches — which is what this arm
// exists to expose. A borrow that wrote a package-level word would collapse
// here even though it looked free in the serial arm.
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

// BenchmarkIsAliveParallel is the cheapest reader there is, polled from every
// core against one enclave — a health probe during shutdown, which is the
// reader the sweep most often meets.
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

			prevUnmap := unmapMemory
			t.Cleanup(func() {
				unmapMemory = prevUnmap
				_, _ = WipeAll(context.Background())
			})
			installStrictUnlock(t)
			unmapMemory = func([]byte) error { return errors.New("munmap: cannot allocate memory") }

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

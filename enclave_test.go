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
	"errors"
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
	if string(got) != "private-key-material" {
		t.Errorf("Open = %q, want %q", got, "private-key-material")
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
	if !e.EqualTo([]byte(material)) {
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
	if !e.EqualTo(material) {
		t.Error("mutating the source changed the enclave: the copy aliases it")
	}

	Wipe(src)
	if !e.EqualTo(material) {
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

	got, err := e.OpenString()
	if err != nil {
		t.Fatalf("OpenString: %v", err)
	}
	if got != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("OpenString = %q, want %q", got, "AKIAIOSFODNN7EXAMPLE")
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
	if e.EqualTo([]byte("transient")) {
		t.Error("EqualTo = true on destroyed enclave")
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
	if e.EqualTo(nil) {
		t.Error("EqualTo = true on nil enclave")
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

	var seen string
	if err := e.WithBytes(func(b []byte) error {
		seen = string(b)
		return nil
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	if seen != "borrowed" {
		t.Errorf("fn saw %q, want %q", seen, "borrowed")
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

	if !e.EqualTo([]byte("compare-me")) {
		t.Error("EqualTo = false for equal material")
	}
	if e.EqualTo([]byte("compare-mE")) {
		t.Error("EqualTo = true for different material")
	}
	if e.EqualTo([]byte("compare")) {
		t.Error("EqualTo = true for a prefix")
	}
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
				t.Errorf("OpenString = %q", s)
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
				_ = e.EqualTo([]byte("private-key-material"))
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

// TestEqualToErrSeparatesMismatchFromDestroyed is the regression for #30.
//
// EqualTo answers false for both "the material differs" and "there is no
// material", so a caller cannot tell them apart. That is safe in the shape it is
// nearly always written in — `if e.EqualTo(secret) { grant() }` fails closed —
// and unsafe the moment the test is inverted, because a destroyed enclave then
// reads as a definite mismatch.
func TestEqualToErrSeparatesMismatchFromDestroyed(t *testing.T) {
	const material = "the real material"

	t.Run("match", func(t *testing.T) {
		e, err := NewMemoryEnclaveFromString(material)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveFromString: %v", err)
		}
		defer e.Destroy()

		equal, err := e.EqualToErr([]byte(material))
		if err != nil {
			t.Fatalf("EqualToErr on a live enclave = %v, want no error", err)
		}
		if !equal {
			t.Error("EqualToErr reported a mismatch for identical material")
		}
	})

	t.Run("genuine mismatch is (false, nil)", func(t *testing.T) {
		e, err := NewMemoryEnclaveFromString(material)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveFromString: %v", err)
		}
		defer e.Destroy()

		equal, err := e.EqualToErr([]byte("something else"))
		if err != nil {
			t.Fatalf("EqualToErr = %v, want no error: the comparison RAN, it "+
				"simply did not match", err)
		}
		if equal {
			t.Error("EqualToErr reported equal for different material")
		}
	})

	t.Run("destroyed is (false, ErrEnclaveDestroyed)", func(t *testing.T) {
		e, err := NewMemoryEnclaveFromString(material)
		if err != nil {
			t.Fatalf("NewMemoryEnclaveFromString: %v", err)
		}
		e.Destroy()

		equal, err := e.EqualToErr([]byte(material))
		if !errors.Is(err, ErrEnclaveDestroyed) {
			t.Fatalf("EqualToErr on a destroyed enclave = (%v, %v), want "+
				"ErrEnclaveDestroyed: a caller that cannot distinguish this "+
				"from a mismatch is acting on a fact it does not have", equal, err)
		}
		if equal {
			t.Error("EqualToErr reported equal for a destroyed enclave")
		}

		// The boolean spelling stays fail-closed, which is why it may keep the
		// collapse: it is the inverted use that is unsafe, and that use now has
		// EqualToErr.
		if e.EqualTo([]byte(material)) {
			t.Error("EqualTo on a destroyed enclave reported true; it must " +
				"fail closed whatever else changes")
		}
	})

	t.Run("nil receiver", func(t *testing.T) {
		var e *MemoryEnclave
		equal, err := e.EqualToErr([]byte(material))
		if !errors.Is(err, ErrEnclaveDestroyed) || equal {
			t.Fatalf("nil EqualToErr = (%v, %v), want (false, ErrEnclaveDestroyed)", equal, err)
		}
		if e.EqualTo([]byte(material)) {
			t.Error("nil EqualTo reported true")
		}
	})
}

// panicValue runs fn and returns what it panicked with, or nil.
func panicValue(fn func()) (r any) {
	defer func() { r = recover() }()
	fn()
	return nil
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

// TestDestroy_CorruptionSurvivesAFailedRelease is the enclave-level half of the
// sticky-corruption regression (#83). A corrupted canary whose release is also
// refused must still PANIC with ErrEnclaveCorrupted — the one condition Destroy
// panics on — keeping the mapping and the charge; and the retry that finally
// releases the pages must report the corruption AGAIN rather than nil, because
// the first attempt's wipe zeroed the very bytes a second verification would
// compare.
func TestDestroy_CorruptionSurvivesAFailedRelease(t *testing.T) {
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
			_ = panicValue(func() { _ = e.Destroy() })
		}
	})
	// VirtualUnlock semantics: the first attempt's munlock succeeds, so a retry
	// that unlocks again is refused on Windows before it reaches the munmap.
	installStrictUnlock(t)
	unmapMemory = func([]byte) error { return denied }

	r := panicValue(func() { _ = e.Destroy() })
	if rerr, ok := r.(error); !ok || !errors.Is(rerr, ErrEnclaveCorrupted) {
		t.Fatalf("Destroy over a corrupted canary with a refused munmap panicked with %v, want ErrEnclaveCorrupted", r)
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
	r = panicValue(func() { _ = e.Destroy() })
	if rerr, ok := r.(error); !ok || !errors.Is(rerr, ErrEnclaveCorrupted) {
		t.Fatalf("the retry that released the pages panicked with %v, want ErrEnclaveCorrupted: "+
			"the corruption detected on the first attempt was lost", r)
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

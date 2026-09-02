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
	"sync/atomic"
	"testing"
	"time"
)

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
	if !e.EqualTo(material) {
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
	if s, err := e.OpenString(); err != nil || s != string(material) {
		t.Errorf("OpenString() = %q, %v; want the material and no error", s, err)
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
	if !moved.EqualTo([]byte("private-key-material")) {
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
	if !copied.EqualTo(src) {
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
// readable — with the failure reported as a typed error. The refusal is real,
// not simulated: mprotect on an unaligned address is EINVAL by definition.
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

	real := e.m.inner
	bad, freeProbe := unmappableSlice(t)
	defer freeProbe()

	e.m.inner = bad
	err = e.Freeze()
	e.m.inner = real

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
	if !e.EqualTo(material) {
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
	if !e.EqualTo(material) {
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
	if remaining := sweep(t); remaining != 0 {
		t.Skipf("the process already holds %d unwipeable enclaves; this test needs a clean ledger", remaining)
	}

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

	remaining, err := WipeAll()
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

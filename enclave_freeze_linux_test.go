// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

package enclave

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"unsafe"

	"github.com/awnumar/memcall"
)

const (
	// sealedMarker selects the child half of the frozen-sized-enclave test.
	sealedMarker = "GO_ENCLAVE_SEALED_WRITE"

	// sealedFroze is printed by the child once Freeze has RETURNED NIL, before
	// the write. The parent requires it, because a child that died for any other
	// reason — a refused allocation, a failed fill, a panic in Freeze — exits
	// non-zero too, and without this marker every one of those would read as
	// proof of a fault the test never observed.
	sealedFroze = "Freeze returned nil; writing through the retained slice now"

	// sealedSurvived is printed by the child if that write RETURNED. Seeing it is
	// the failure this issue exists to close: the pages were not protected and a
	// stray write corrupts key material with nothing to announce it.
	sealedSurvived = "wrote through a frozen sized enclave and lived"
)

// TestMemoryEnclave_FrozenSizedPagesFault is the execution evidence for
// Freeze: the property is that a write through a retained slice FAULTS, and a
// property about faults is not established by asserting a bool that a
// bookkeeping bug could set on its own.
//
// The two halves have to run in different processes because they have different
// success conditions. The write BEFORE the freeze must return — that is the fill
// path, and an implementation that froze a sized enclave at construction would
// break every consumer of it — so it runs here, in-process. The write AFTER the
// freeze must kill the process: the fault is at a mapped-but-read-only address
// outside the Go heap, which the runtime reports as an unrecoverable fault
// rather than a catchable panic. So the child's evidence is inverted — it must
// die, and must not have printed the survival marker on its way.
//
// The in-process half is also the control in the strict sense: it is the same
// enclave shape, the same retained slice and the same store, differing only in
// whether Freeze ran. Without it a child that faulted for an unrelated reason
// would look like a pass.
func TestMemoryEnclave_FrozenSizedPagesFault(t *testing.T) {
	if os.Getenv(sealedMarker) == "1" {
		sealedWriteChild(t)
		return
	}

	// Control: unfrozen, the same write succeeds. This is the fill path.
	unfrozen, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	view, err := unfrozen.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	view[0] = 0xFF // must not fault: nothing has frozen these pages
	if !unfrozen.EqualTo(append([]byte{0xFF}, make([]byte, 31)...)) {
		t.Error("the write into an unfrozen sized enclave did not take")
	}
	unfrozen.Destroy()

	cmd := exec.Command(os.Args[0], "-test.run=^TestMemoryEnclave_FrozenSizedPagesFault$", "-test.v")
	cmd.Env = append(os.Environ(), sealedMarker+"=1")
	out, cerr := cmd.CombinedOutput()

	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("child skipped:\n%s", out)
	}
	if !strings.Contains(string(out), sealedFroze) {
		t.Fatalf("the child never reported a successful Freeze, so whatever it did next proves nothing:\n%s", out)
	}
	if strings.Contains(string(out), sealedSurvived) {
		t.Fatalf("a write through a frozen sized enclave returned instead of faulting; "+
			"Freeze did not protect the pages:\n%s", out)
	}
	if cerr == nil {
		t.Fatalf("the child exited cleanly after writing to frozen pages; it should have faulted:\n%s", out)
	}
}

func sealedWriteChild(t *testing.T) {
	t.Helper()

	e, err := NewMemoryEnclaveSized(32)
	if err != nil {
		t.Skipf("could not allocate: %v", err)
	}

	// Fill exactly as a consumer would, and retain the slice past the borrow,
	// which is the mistake the freeze is meant to make loud.
	view, err := e.Open()
	if err != nil {
		t.Skipf("Open: %v", err)
	}
	copy(view, []byte("0123456789abcdef0123456789abcdef"))

	if err := e.Freeze(); err != nil {
		t.Skipf("Freeze: %v", err)
	}
	fmt.Println(sealedFroze)

	// The write the freeze exists to stop.
	view[0] = 0xFF

	fmt.Println(sealedSurvived)
	e.Destroy()
}

// TestMemoryEnclave_FrozenDestroyFallsBackToUnmap is the interaction between
// this branch and #38, and it is the pairing that makes both changes matter.
//
// #38 gave the release path a bare-munmap fallback because a frozen enclave
// skips wipeAndVerify's early wipe — its pages are read-only, so there is
// nothing it may write — and a PERMANENTLY denied mprotect would otherwise leave
// the material resident in locked memory for the process lifetime. Until this
// branch, "frozen" and "built from existing material" were the same set. Freeze
// puts SIZED enclaves into it, so the fallback now has to cover a class of
// enclave it was never exercised against: one with an Allocator reservation
// behind it, frozen after construction rather than during it.
//
// Three things are asserted, and the middle one is the point: the condition is
// REPORTED through DestroyErr, the pages are actually GONE from the process's
// mappings, and the locked-memory accounting comes back — a fallback that
// unmapped without the kernel dropping the mlock charge would leak a locked page
// per teardown under a seccomp policy, which is exactly the environment where
// pages are scarcest.
func TestMemoryEnclave_FrozenDestroyFallsBackToUnmap(t *testing.T) {
	a, err := NewAllocator(8 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	lockedBefore, err := vmLckBytes()
	if err != nil {
		t.Skipf("cannot read VmLck: %v", err)
	}

	e, err := a.NewSized(64)
	if err != nil {
		t.Fatalf("NewSized: %v", err)
	}
	if err := e.WithBytes(func(b []byte) error {
		copy(b, bytes.Repeat([]byte{0x7E}, len(b)))
		return nil
	}); err != nil {
		t.Fatalf("filling the enclave: %v", err)
	}
	if err := e.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	if e.m.mutable {
		t.Fatal("the enclave is not frozen, so this test would not reach the path it exists for")
	}

	addr := uintptr(unsafe.Pointer(&e.m.memory[0]))
	if !mappedAt(t, addr) {
		t.Fatal("the region is not mapped before the teardown; the assertion after it would be vacuous")
	}
	if reserved := a.InUse(); reserved == 0 {
		t.Fatal("nothing was reserved; the budget half of this test would be vacuous")
	}

	denied := errors.New("mprotect denied by policy")
	prev := protectMemory
	t.Cleanup(func() { protectMemory = prev })
	protectMemory = func([]byte, memcall.MemoryProtectionFlag) error { return denied }

	derr := e.DestroyErr()

	if !errors.Is(derr, ErrReleasedWithoutWipe) {
		t.Fatalf("DestroyErr = %v, want ErrReleasedWithoutWipe: a frozen sized enclave whose release "+
			"mprotect is denied must take the unmap fallback and say so", derr)
	}
	if !errors.Is(derr, denied) {
		t.Errorf("DestroyErr = %v, want the underlying refusal reachable through errors.Is", derr)
	}
	if mappedAt(t, addr) {
		t.Fatal("the region is STILL MAPPED after the teardown: a frozen sized enclave's material " +
			"is resident in locked memory for the process lifetime")
	}
	if e.IsAlive() {
		t.Error("the enclave reports itself alive over memory the kernel has taken back")
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("the Allocator still holds %d bytes reserved; the pages went back, so the "+
			"reservation must have too", used)
	}

	// The kernel's own accounting, not this package's. munmap drops the mlock
	// charge with the mapping; if it did not, every teardown under a denying
	// policy would leak a page of the process's RLIMIT_MEMLOCK budget.
	lockedAfter, err := vmLckBytes()
	if err != nil {
		t.Fatalf("cannot read VmLck: %v", err)
	}
	if lockedAfter > lockedBefore {
		t.Errorf("VmLck = %d after the fallback, was %d before the enclave existed: the unmap did not "+
			"return the locked charge", lockedAfter, lockedBefore)
	}
}

// TestMemoryEnclave_FreezeIsWhatPutsMaterialOnTheFallbackPath measures the COST
// this branch's doc comment claims, instead of asserting it.
//
// The claim is that freezing moves the material's wipe behind a syscall that can
// be refused: wipeAndVerify overwrites the data BEFORE the mprotect while the
// region is still writable, and skips that early wipe exactly when the pages are
// read-only. So under a denied mprotect an unfrozen sized enclave reaches the
// fallback with its material already zeroed, and a frozen one reaches it with
// the material still there — which is why #38's fallback exists at all.
//
// Both halves run, because either alone proves nothing: if the frozen case did
// not carry live material the fallback would be unnecessary, and if the unfrozen
// case did too then the early wipe would not be doing anything. The observation
// is taken from inside the unmap seam, the one instant where the pages are still
// mapped and the decision has already been made.
func TestMemoryEnclave_FreezeIsWhatPutsMaterialOnTheFallbackPath(t *testing.T) {
	material := bytes.Repeat([]byte{0x9D}, 64)

	for _, tc := range []struct {
		name         string
		freeze       bool
		wantResidual bool
	}{
		{name: "unfrozen: wiped before the denied mprotect", freeze: false, wantResidual: false},
		{name: "frozen: still resident when the fallback runs", freeze: true, wantResidual: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Unexported: this test lets the release run without Destroy, and the
			// exported constructor would leave a live ledger entry behind for
			// every WipeAll test in the package to count.
			e, err := newMemoryEnclaveSized(len(material))
			if err != nil {
				t.Fatalf("newMemoryEnclaveSized: %v", err)
			}
			copy(e.m.data, material)
			if tc.freeze {
				if err := e.Freeze(); err != nil {
					t.Fatalf("Freeze: %v", err)
				}
			}
			if e.m.mutable == tc.freeze {
				t.Fatalf("mutable = %v with freeze = %v; the case under test is not set up",
					e.m.mutable, tc.freeze)
			}

			// Read the data region at the moment the fallback is about to hand
			// the pages back. Frozen pages are read-only, not inaccessible, so
			// this read is safe in both arms.
			view := e.m.data
			var atUnmap []byte
			prevProtect, prevUnmap := protectMemory, unmapDirectFn
			t.Cleanup(func() { protectMemory, unmapDirectFn = prevProtect, prevUnmap })
			protectMemory = func([]byte, memcall.MemoryProtectionFlag) error {
				return errors.New("mprotect denied by policy")
			}
			unmapDirectFn = func(b []byte) error {
				atUnmap = append([]byte(nil), view...)
				return prevUnmap(b)
			}

			if rerr := e.m.release(); !errors.Is(rerr, ErrReleasedWithoutWipe) {
				t.Fatalf("release = %v, want ErrReleasedWithoutWipe", rerr)
			}
			if atUnmap == nil {
				t.Fatal("the unmap fallback never ran, so nothing was measured")
			}

			residual := !bytes.Equal(atUnmap, make([]byte, len(material)))
			if residual != tc.wantResidual {
				t.Errorf("material still resident at the unmap = %v, want %v", residual, tc.wantResidual)
			}
			if tc.wantResidual && !bytes.Equal(atUnmap, material) {
				t.Errorf("the frozen arm reached the fallback with something other than the material; "+
					"got %#x", atUnmap[:8])
			}
		})
	}
}

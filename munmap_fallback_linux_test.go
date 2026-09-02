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
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/awnumar/memcall"
)

// mappedAt reports whether addr still falls inside any mapping of this process.
//
// This is the assertion #12 asks for and the reason the test is not merely
// "an error came back": the defect it guards against is material left RESIDENT,
// so the test has to establish that the pages are gone, not that a function
// returned. Reading /proc/self/maps does that without dereferencing an address
// that may or may not still be mapped -- touching it to find out would either
// succeed silently or kill the test process, and neither is an assertion.
func mappedAt(t *testing.T, addr uintptr) bool {
	t.Helper()

	f, err := os.Open("/proc/self/maps")
	if err != nil {
		t.Fatalf("open /proc/self/maps: %v", err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		dash := strings.IndexByte(line, '-')
		sp := strings.IndexByte(line, ' ')
		if dash < 0 || sp < 0 || sp < dash {
			continue
		}
		lo, err1 := strconv.ParseUint(line[:dash], 16, 64)
		hi, err2 := strconv.ParseUint(line[dash+1:sp], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if uint64(addr) >= lo && uint64(addr) < hi {
			return true
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan /proc/self/maps: %v", err)
	}
	return false
}

// TestFrozenReleaseUnmapsWhenMprotectIsDenied is the regression for #12.
//
// A frozen enclave skips wipeAndVerify's early wipe -- its pages are read-only,
// so there is nothing it may write -- and can only be cleared through the
// release mprotect that makes the region writable again. Under a PERMANENT
// denial of that mprotect the old code returned an error and kept the mapping,
// leaving the secret resident in locked memory for the process lifetime.
//
// The fix hands the pages back with a bare munmap instead. This asserts the
// pages are actually GONE, and that the outcome is reported rather than passed
// off as an ordinary release.
func TestFrozenReleaseUnmapsWhenMprotectIsDenied(t *testing.T) {
	secret := []byte("material that must not stay resident")

	// newMemoryEnclave, NOT NewMemoryEnclave: this test drives m.release()
	// directly rather than Destroy(), and Destroy is what deregisters. The
	// exported constructor publishes to the shutdown ledger, so using it here
	// leaves a live entry behind and every WipeAll test in the package then
	// counts it -- measured, on the first version of this file.
	e, err := newMemoryEnclave(append([]byte(nil), secret...))
	if err != nil {
		t.Fatalf("newMemoryEnclave: %v", err)
	}

	// The mapping is frozen by this constructor; if that ever stops being true
	// the test is no longer exercising the case it exists for.
	if e.m.mutable {
		t.Fatal("enclave is not frozen, so this test would pass without " +
			"covering the frozen path #12 is about")
	}

	addr := uintptr(unsafe.Pointer(&e.m.memory[0]))
	if !mappedAt(t, addr) {
		t.Fatal("the region is not mapped before release, so the assertion " +
			"after it would be vacuous")
	}

	denied := errors.New("mprotect denied by policy")
	previous := protectMemory
	t.Cleanup(func() { protectMemory = previous })
	protectMemory = func([]byte, memcall.MemoryProtectionFlag) error { return denied }

	rerr := e.m.release()

	if !errors.Is(rerr, ErrReleasedWithoutWipe) {
		t.Fatalf("release = %v, want ErrReleasedWithoutWipe: a denied mprotect "+
			"on a frozen enclave must fall back to unmapping, and must say so", rerr)
	}
	if !errors.Is(rerr, denied) {
		t.Errorf("release = %v, want the underlying mprotect refusal reachable "+
			"through errors.Is; an operator needs to know what denied it", rerr)
	}

	// The point of the whole exercise.
	if mappedAt(t, addr) {
		t.Fatal("the region is STILL MAPPED after release: the material is " +
			"resident in locked memory for the process lifetime, which is " +
			"exactly the defect #12 reports")
	}

	if e.m.memory != nil || e.m.data != nil || e.m.inner != nil {
		t.Error("the mapping kept its slices after the pages were unmapped; a " +
			"reader would be looking at memory the kernel has taken back")
	}
}

// TestFrozenReleaseKeepsTheMappingWhenTheBypassAlsoFails pins the other half:
// when the fallback cannot run either, nothing is dropped.
//
// Losing the handle there would strand a region that is still mapped, possibly
// still locked and possibly still holding material, with no way to retry -- and
// would tell an Allocator those bytes are free while the kernel still holds them.
func TestFrozenReleaseKeepsTheMappingWhenTheBypassAlsoFails(t *testing.T) {
	e, err := newMemoryEnclave([]byte("material"))
	if err != nil {
		t.Fatalf("newMemoryEnclave: %v", err)
	}
	t.Cleanup(func() {
		if e.m != nil {
			_ = e.m.release()
		}
	})

	denied := errors.New("mprotect denied by policy")
	prevProtect := protectMemory
	prevUnmap := unmapDirectFn
	t.Cleanup(func() { protectMemory, unmapDirectFn = prevProtect, prevUnmap })
	protectMemory = func([]byte, memcall.MemoryProtectionFlag) error { return denied }
	unmapDirectFn = func([]byte) error { return errors.New("munmap denied too") }

	rerr := e.m.release()

	if errors.Is(rerr, ErrReleasedWithoutWipe) {
		t.Fatalf("release = %v, want a failure: the bypass did not run, so "+
			"claiming an unwiped RELEASE would report pages returned that were not", rerr)
	}
	if e.m.memory == nil {
		t.Fatal("the mapping was dropped although the pages are still mapped; " +
			"there is now no handle to retry the release through")
	}
}

// TestWipeAllAccountsAnUnwipedRelease is the regression for the sweep half.
//
// releaseLocked clears the mapping for an unwiped release -- the pages ARE gone --
// so a sweep that still treated only nil and ErrEnclaveCorrupted as released
// left the enclave registered with its Allocator reservation unreturned, and
// reported it as still held. A retry on a later pass then saw a nil error and
// the mprotect denial vanished entirely.
//
// Asserts all three: the count, the reservation, and that the condition is
// REPORTED rather than swallowed.
func TestWipeAllAccountsAnUnwipedRelease(t *testing.T) {
	a, err := NewAllocator(1 << 20)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := a.New([]byte("material the sweep must account for"))
	if err != nil {
		t.Fatalf("Allocator.New: %v", err)
	}
	if e.m.mutable {
		t.Fatal("enclave is not frozen; this test would not exercise the path")
	}

	denied := errors.New("mprotect denied by policy")
	prev := protectMemory
	t.Cleanup(func() { protectMemory = prev })
	protectMemory = func([]byte, memcall.MemoryProtectionFlag) error { return denied }

	remaining, werr := WipeAll()

	if remaining != 0 {
		t.Errorf("WipeAll = %d remaining, want 0: the pages were unmapped, so "+
			"the enclave is not still held and must not be counted", remaining)
	}
	if !errors.Is(werr, ErrReleasedWithoutWipe) {
		t.Errorf("WipeAll error = %v, want ErrReleasedWithoutWipe: a sweep that "+
			"swallows the mprotect denial hides it on the one path a shutdown "+
			"actually runs", werr)
	}
	if used := a.InUse(); used != 0 {
		t.Errorf("allocator still holds %d bytes reserved after the sweep; the "+
			"pages went back, so the reservation must have too", used)
	}
}

// TestDestroyErrReportsTheDeniedMprotect pins the public path.
//
// Destroy correctly does NOT panic on an unwiped release -- nothing was corrupted
// and the invariant held -- but that left no channel at all, so the pattern this
// library is actually used through, `defer e.Destroy()`, reported success while
// the environment silently denied the wipe-enabling mprotect on every frozen
// enclave. The denial reaches every other enclave in the process, so losing it
// on the main path loses it everywhere.
func TestDestroyErrReportsTheDeniedMprotect(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("material for the public teardown path"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}

	denied := errors.New("mprotect denied by policy")
	prev := protectMemory
	t.Cleanup(func() { protectMemory = prev })
	protectMemory = func([]byte, memcall.MemoryProtectionFlag) error { return denied }

	if derr := e.DestroyErr(); !errors.Is(derr, ErrReleasedWithoutWipe) {
		t.Fatalf("DestroyErr = %v, want ErrReleasedWithoutWipe", derr)
	}
	if e.IsAlive() {
		t.Error("the enclave reports itself alive after DestroyErr")
	}

	// Idempotent, and a second call has nothing left to report.
	if derr := e.DestroyErr(); derr != nil {
		t.Errorf("second DestroyErr = %v, want nil", derr)
	}
}

// TestDestroyErrIsNilOnAnOrdinaryTeardown is the control that makes the test
// above mean something: without it, an implementation that returned the sentinel
// unconditionally would pass.
func TestDestroyErrIsNilOnAnOrdinaryTeardown(t *testing.T) {
	e, err := NewMemoryEnclave([]byte("material"))
	if err != nil {
		t.Fatalf("NewMemoryEnclave: %v", err)
	}
	if derr := e.DestroyErr(); derr != nil {
		t.Fatalf("DestroyErr on a clean teardown = %v, want nil", derr)
	}
}

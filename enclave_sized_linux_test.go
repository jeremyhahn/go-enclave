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
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestNewMemoryEnclaveSized_MemoryIsLocked asks the kernel whether the region a
// sized enclave hands to its filler is actually mlock'd, rather than trusting
// that memguard did what its documentation says.
//
// This is the half of the generate-in-place claim that
// TestNewMemoryEnclaveSized_FillsInPlace cannot make: that test proves the
// generator wrote into the enclave's own storage, and this one proves that
// storage is locked memory. A constructor that quietly fell back to an ordinary
// allocation would satisfy the first and fail here.
//
// The yardstick is an ordinary heap allocation, read from the same /proc file by
// the same parser, and it is established BEFORE the enclave exists — so a
// process that turned out to be mlockall'd, or a kernel that does not report the
// field, skips rather than passing for the wrong reason.
func TestNewMemoryEnclaveSized_MemoryIsLocked(t *testing.T) {
	heap := make([]byte, os.Getpagesize())
	for i := range heap {
		heap[i] = 1 // fault the page in so it has a mapping to find
	}
	heapAddr, err := sliceAddr(heap)
	if err != nil {
		t.Fatalf("heap address: %v", err)
	}
	heapKB, found, err := lockedKBForAddress(heapAddr)
	if err != nil {
		t.Skipf("cannot read /proc/self/smaps: %v", err)
	}
	if !found {
		t.Skipf("no smaps entry with a Locked: field covers ordinary heap memory at %#x", heapAddr)
	}
	if heapKB != 0 {
		t.Skipf("ordinary heap memory reports %d kB locked; this process cannot distinguish locked from unlocked", heapKB)
	}
	runtime.KeepAlive(heap)

	e, err := NewMemoryEnclaveSized(64)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	defer e.Destroy()

	var addr uintptr
	if err := e.WithBytes(func(b []byte) error {
		var aerr error
		addr, aerr = sliceAddr(b)
		return aerr
	}); err != nil {
		t.Fatalf("borrow: %v", err)
	}

	kb, found, err := lockedKBForAddress(addr)
	if err != nil {
		t.Fatalf("cannot read /proc/self/smaps: %v", err)
	}
	if !found {
		t.Fatalf("no smaps entry covers the borrowed region at %#x", addr)
	}
	if kb == 0 {
		t.Fatalf("the borrowed region at %#x reports 0 kB locked; a sized enclave's memory is not mlocked", addr)
	}
}

// sliceAddr returns the address of a slice's first element. It goes through the
// fmt verb rather than unsafe so that a test asserting a memory property does
// not itself need the unsafe package.
func sliceAddr(b []byte) (uintptr, error) {
	var addr uint64
	if _, err := fmt.Sscanf(fmt.Sprintf("%p", b), "0x%x", &addr); err != nil {
		return 0, fmt.Errorf("parsing slice address: %w", err)
	}
	return uintptr(addr), nil
}

// lockedKBForAddress reports the Locked: figure of the /proc/self/smaps mapping
// that contains addr. found is false when no mapping covers addr, or when the
// kernel does not emit the field for it.
func lockedKBForAddress(addr uintptr) (kb int64, found bool, err error) {
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		return 0, false, err
	}
	defer f.Close()

	inRange := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if lo, hi, ok := parseSmapsHeader(line); ok {
			inRange = addr >= lo && addr < hi
			continue
		}
		if !inRange || !strings.HasPrefix(line, "Locked:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false, fmt.Errorf("malformed smaps line %q", line)
		}
		v, perr := strconv.ParseInt(fields[1], 10, 64)
		if perr != nil {
			return 0, false, fmt.Errorf("malformed smaps line %q: %w", line, perr)
		}
		return v, true, nil
	}
	return 0, false, sc.Err()
}

// parseSmapsHeader recognizes an smaps mapping header ("7f0c…-7f0c… rw-p …")
// and returns its bounds. The per-mapping detail lines that follow it never
// parse as one, so this is what separates the two.
func parseSmapsHeader(line string) (lo, hi uintptr, ok bool) {
	first, _, cut := strings.Cut(line, " ")
	if !cut {
		return 0, 0, false
	}
	l, r, cut := strings.Cut(first, "-")
	if !cut {
		return 0, 0, false
	}
	lv, err := strconv.ParseUint(l, 16, 64)
	if err != nil {
		return 0, 0, false
	}
	rv, err := strconv.ParseUint(r, 16, 64)
	if err != nil {
		return 0, 0, false
	}
	return uintptr(lv), uintptr(rv), true
}

const (
	// sizedAdmissionMarker selects the child half of the admission-ordering test.
	sizedAdmissionMarker = "GO_ENCLAVE_SIZED_ADMISSION"

	// sizedRefusalConfirmed is logged by the child once an over-budget NewSized
	// has been refused as a BUDGET refusal with the process's locked-memory
	// ceiling already exhausted — the answer the mapping layer could not have
	// given, since under that ceiling it can only fail to lock.
	sizedRefusalConfirmed = "over-budget NewSized was refused by admission, not by the kernel"

	// sizedFaultArmed is logged by the child once it has shown the lock fault
	// was live during that refusal, by taking the same allocation unadmitted and
	// watching the kernel refuse it. Without this the test would pass vacuously
	// on any run where the injected ceiling never bit.
	sizedFaultArmed = "the injected ceiling was live: the same allocation, unadmitted, was refused by the kernel"

	// sizedNoCollateral is logged once the child has confirmed an unrelated
	// enclave survived BOTH refusals. Before v0.3.0-alpha the unadmitted one
	// destroyed it: memguard purged every live buffer in the process on its way
	// to reporting the failure.
	sizedNoCollateral = "an unrelated enclave survived both refusals intact"

	// sizedReservationReleased is logged by the child once it has observed that a
	// lock failure UNDER admission returned the reservation to the allocator.
	sizedReservationReleased = "NewSized released its reservation on a lock failure"
)

// TestAllocator_NewSized_RefusalNeverAttemptsMapping proves the ordering
// [Allocator.NewSized] promises: admission decides BEFORE any memory is mapped
// or locked.
//
// The discriminator is the sentinel, and under this design that is sound in a
// way it was not before v0.3.0-alpha. Back then a typed error proved nothing on
// its own — ErrLockedMemoryUnavailable came back from the far side of a
// process-wide purge, so the damage was already done and the test had to watch
// an unrelated canary enclave die to tell the two paths apart. There is no purge
// now: ErrBudgetExhausted can only come from admission and
// ErrLockedMemoryUnavailable only from the kernel refusing the lock, so which
// one arrives says which layer refused.
//
// The canary is still here, asserting the property that replaced it: it must
// survive BOTH refusals, including the unadmitted one that used to destroy it.
//
// It runs in a subprocess because the fault is injected process-wide.
func TestAllocator_NewSized_RefusalNeverAttemptsMapping(t *testing.T) {
	if os.Getenv(sizedAdmissionMarker) == "1" {
		sizedAdmissionChild(t)
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestAllocator_NewSized_RefusalNeverAttemptsMapping$", "-test.v")
	cmd.Env = append(os.Environ(), sizedAdmissionMarker+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if strings.Contains(string(out), "--- SKIP") {
		t.Skipf("subprocess could not inject the fault:\n%s", out)
	}
	for _, want := range []string{sizedRefusalConfirmed, sizedFaultArmed, sizedNoCollateral, sizedReservationReleased} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("subprocess did not confirm %q:\n%s", want, out)
		}
	}
}

func sizedAdmissionChild(t *testing.T) {
	t.Helper()

	const material = "canary-key-material"

	// Allocated while locked memory is still available, and never touched by
	// the allocator under test.
	canary, err := NewMemoryEnclave([]byte(material))
	if err != nil {
		t.Skipf("could not allocate the canary enclave: %v", err)
	}

	// A budget far below what is requested below, so admission is the only
	// thing that can refuse.
	a, err := NewAllocator(16)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var original unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &original); err != nil {
		t.Skipf("cannot read RLIMIT_MEMLOCK: %v", err)
	}
	// Lowering the soft limit does not unlock pages already locked, so the
	// canary stays intact; only subsequent allocations fail.
	limit := unix.Rlimit{Cur: uint64(os.Getpagesize()), Max: original.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		t.Skipf("cannot lower RLIMIT_MEMLOCK: %v", err)
	}

	const request = 4096

	e, err := a.NewSized(request)
	if e != nil {
		t.Fatal("over-budget NewSized returned a non-nil enclave")
	}
	if !errors.Is(err, ErrBudgetExhausted) {
		t.Fatalf("err = %v, want ErrBudgetExhausted", err)
	}
	if errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatal("the request reached the mapping layer; admission did not decide first")
	}
	if a.InUse() != 0 {
		t.Fatalf("InUse = %d after the refusal, want 0", a.InUse())
	}
	t.Log(sizedRefusalConfirmed)

	// Non-vacuity. The same allocation, taken without admission, must be
	// refused by the KERNEL under the ceiling that was already in force above —
	// which is what shows the ceiling was live and the different answer above
	// came from admission rather than from luck.
	if _, err := NewMemoryEnclaveSized(request); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("unadmitted NewMemoryEnclaveSized err = %v, want ErrLockedMemoryUnavailable; "+
			"the ceiling was not live and the refusal above proves nothing", err)
	}
	t.Log(sizedFaultArmed)

	// Neither refusal may touch anything else. The unadmitted one is the
	// interesting half: before v0.3.0-alpha it purged the process here and this
	// enclave came back dead.
	if !canary.IsAlive() {
		t.Fatal("an unrelated enclave died during a refusal")
	}
	if !canary.EqualTo([]byte(material)) {
		t.Fatal("the canary's material did not survive the refusals")
	}
	t.Log(sizedNoCollateral)

	// With the ceiling still in force, an ADMITTED sized allocation that the OS
	// then refuses must give its reservation back, so a transient exhaustion
	// does not shrink the budget permanently. There is no enclave to inspect —
	// only the counter records whether the release path ran, which makes this
	// the mutation killer for `a.used.Add(-charge)` in NewSized.
	big, err := NewAllocator(1 << 24)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}
	if _, err := big.NewSized(request); !errors.Is(err, ErrLockedMemoryUnavailable) {
		t.Fatalf("admitted NewSized err = %v, want ErrLockedMemoryUnavailable", err)
	}
	if got := big.InUse(); got != 0 {
		t.Fatalf("InUse = %d after a lock failure, want 0 (the failed allocation leaked its reservation)", got)
	}
	t.Log(sizedReservationReleased)
}

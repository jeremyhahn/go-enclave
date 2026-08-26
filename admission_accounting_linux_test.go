// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-enclave.
//
// go-enclave is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build linux

package enclave

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// vmLckBytes reports the process's total mlock'd bytes from
// /proc/self/status. This is the kernel's own RLIMIT_MEMLOCK accounting — the
// exact quantity an Allocator budget claims to be comparable to.
func vmLckBytes() (int64, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "VmLck:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed VmLck line %q", line)
		}
		kb, perr := strconv.ParseInt(fields[1], 10, 64)
		if perr != nil {
			return 0, fmt.Errorf("malformed VmLck line %q: %w", line, perr)
		}
		return kb * 1024, nil
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("no VmLck line in /proc/self/status")
}

// TestAllocator_ChargesWhatTheKernelLocks is the conformance test for the
// accounting unit, and the one assertion here that cannot rot.
//
// Every other test in this package compares the allocator against
// roundToPageSize semantics that this package itself implements — so if the
// assumption underneath were wrong, or memguard changed what it locks, they
// would all agree with each other and all be wrong together. This one takes its
// yardstick from the KERNEL: it reads VmLck before and after each allocation and
// requires the allocator's reservation to equal the locked bytes the kernel
// actually charged.
//
// That is what makes the budget comparable to RLIMIT_MEMLOCK, which is the
// entire claim the Allocator rests on. If memguard ever starts locking the guard
// pages too, the reservation silently becomes an undercount again and only a
// kernel-sourced yardstick notices.
func TestAllocator_ChargesWhatTheKernelLocks(t *testing.T) {
	if _, err := vmLckBytes(); err != nil {
		t.Skipf("cannot read VmLck from /proc/self/status: %v", err)
	}

	a, err := NewAllocator(64 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// Probe first. If mlock is not effective here — a container without
	// CAP_IPC_LOCK, a kernel that does not account it — every delta below is
	// zero and the comparison would be vacuous rather than informative.
	probeBefore, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}
	probe, err := a.NewSized(1)
	if err != nil {
		t.Fatalf("probe NewSized(1): %v", err)
	}
	probeAfter, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}
	probe.Destroy()
	if probeAfter-probeBefore == 0 {
		t.Skipf("allocating an enclave moved VmLck by 0 bytes; mlock is not accounted in this environment")
	}

	for _, size := range []int{1, 32, int(pageSize) - 1, int(pageSize), int(pageSize) + 1, 3*int(pageSize) - 1} {
		t.Run(fmt.Sprintf("%d", size), func(t *testing.T) {
			lockedBefore, err := vmLckBytes()
			if err != nil {
				t.Fatalf("VmLck: %v", err)
			}
			usedBefore := a.InUse()

			e, err := a.NewSized(size)
			if err != nil {
				t.Fatalf("NewSized(%d): %v", size, err)
			}

			lockedAfter, err := vmLckBytes()
			if err != nil {
				t.Fatalf("VmLck: %v", err)
			}
			kernel := lockedAfter - lockedBefore
			charged := a.InUse() - usedBefore

			if charged != kernel {
				t.Errorf("allocator charged %d bytes for a %d-byte enclave; the kernel locked %d",
					charged, size, kernel)
			}

			// Releasing must return exactly what was taken, on both sides.
			e.Destroy()
			lockedFinal, err := vmLckBytes()
			if err != nil {
				t.Fatalf("VmLck: %v", err)
			}
			if got := a.InUse(); got != usedBefore {
				t.Errorf("InUse = %d after Destroy, want the pre-allocation %d", got, usedBefore)
			}
			if lockedFinal != lockedBefore {
				t.Errorf("VmLck = %d after Destroy, want the pre-allocation %d", lockedFinal, lockedBefore)
			}
		})
	}
}

// TestAllocator_BudgetHoldsTheEnclavesItPromises is the consequence of the unit
// being right, stated the way an operator would state it: a budget of N pages
// holds N enclaves and refuses the next one, whatever their material's size.
//
// Under byte accounting the same 5-page budget — 20480 bytes on a 4 KiB-page
// host — "held" 640 thirty-two-byte enclaves, because it charged them 32 bytes
// each. Those 640 enclaves lock 640 pages: 2621440 bytes, 128x the budget's own
// limit. That is the defect, expressed as behavior rather than as arithmetic.
func TestAllocator_BudgetHoldsTheEnclavesItPromises(t *testing.T) {
	const capacity = 5
	a, err := NewAllocator(capacity * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var held []*MemoryEnclave
	defer func() {
		for _, e := range held {
			e.Destroy()
		}
	}()

	for i := 0; i < capacity; i++ {
		e, err := a.NewSized(32)
		if err != nil {
			t.Fatalf("NewSized #%d of %d: %v (the budget does not hold what it promises)", i+1, capacity, err)
		}
		held = append(held, e)
	}

	if _, err := a.NewSized(32); err == nil {
		t.Fatalf("a %d-page budget admitted a %dth enclave; each one locks a whole page",
			capacity, capacity+1)
	}

	if got := a.InUse(); got != capacity*pageSize {
		t.Errorf("InUse = %d, want the full %d", got, capacity*pageSize)
	}
	if locked, err := vmLckBytes(); err == nil && locked < capacity*pageSize {
		t.Errorf("kernel reports %d locked bytes for %d enclaves, want at least %d",
			locked, capacity, capacity*pageSize)
	}
}

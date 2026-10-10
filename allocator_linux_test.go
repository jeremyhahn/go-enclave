// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
)

// vmLckBytes reports the process's total mlock'd bytes from /proc/self/status,
// the kernel's own RLIMIT_MEMLOCK accounting.
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

// TestAllocator_ChargesWhatTheKernelLocks pins the accounting unit against the
// kernel: each allocation's reservation must equal the change in VmLck, and
// Destroy must return both. Other tests compare against this package's own
// page rounding, so only this one would notice if guard pages started being
// locked or the rounding were wrong.
func TestAllocator_ChargesWhatTheKernelLocks(t *testing.T) {
	a, err := NewAllocator(64 * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	// Probe first: if the kernel does not account mlock, every delta below is
	// zero and the comparison would be vacuous.
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
		t.Fatal("allocating an enclave moved VmLck by 0 bytes: the kernel is not accounting mlock, so every " +
			"comparison below would be vacuous. The runner must be a real Linux kernel that reports VmLck " +
			"in /proc/self/status (see vmLckBytes)")
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

// TestAllocator_BudgetHoldsTheEnclavesItPromises pins that a budget of N pages
// holds N enclaves and refuses the next, whatever their material's size.
func TestAllocator_BudgetHoldsTheEnclavesItPromises(t *testing.T) {
	const capacity = 5
	a, err := NewAllocator(capacity * pageSize)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	var held []*Memory
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

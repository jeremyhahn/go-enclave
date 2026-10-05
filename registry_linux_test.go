// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

// TestWipeAll_LeavesNoResidentMaterial pins that after the sweep no material
// this package held is anywhere in process memory. It scans every anonymous
// mapping, named or not. The control comes first: with the enclaves alive the
// material must be found outside the needle's own mapping.
func TestWipeAll_LeavesNoResidentMaterial(t *testing.T) {
	// The needle lives in a raw mapping, not a MemoryEnclave: WipeAll would
	// destroy an enclave holding it, and a []byte literal would put it on the heap.
	m, err := newMapping(64)
	if err != nil {
		t.Fatalf("newMapping: %v", err)
	}
	defer func() {
		if err := m.release(); err != nil {
			t.Errorf("releasing the needle mapping: %v", err)
		}
	}()
	if _, err := io.ReadFull(rand.Reader, m.data); err != nil {
		t.Fatalf("generating the needle: %v", err)
	}
	home, err := sliceAddr(m.data)
	if err != nil {
		t.Fatalf("needle address: %v", err)
	}

	// Several enclaves, so the sweep has more than one copy to find.
	const copies = 4
	for i := 0; i < copies; i++ {
		// From a locked transfer enclave, never a heap copy: NewMemoryEnclave
		// wipes its input, and that wipe must land in locked pages.
		transfer, err := NewMemoryEnclaveSized(len(m.data))
		if err != nil {
			t.Fatalf("allocating the transfer enclave: %v", err)
		}
		if err := transfer.WithBytes(func(dst []byte) error {
			copy(dst, m.data)
			_, nerr := NewMemoryEnclave(dst)
			return nerr
		}); err != nil {
			t.Fatalf("NewMemoryEnclave: %v", err)
		}
		if err := transfer.Destroy(); err != nil {
			t.Fatalf("destroying the transfer enclave: %v", err)
		}
	}

	// Control: with the enclaves alive the material must be findable outside
	// the needle's mapping, proving the scan sees where a leak would live.
	withLive, err := processMemoryFind(m.data)
	if err != nil {
		t.Fatalf("cannot sweep process memory: %v (see processMemoryFind for what the runner must allow)", err)
	}
	if outside := rangesOutside(withLive, home); len(outside) == 0 {
		t.Fatalf("the sweep found no match outside the needle's own mapping while %d enclaves held the "+
			"material (%d matches total); it cannot see the mappings a leak would live in and a negative "+
			"result would be vacuous", copies, len(withLive))
	}

	if remaining := sweep(t); remaining != 0 {
		t.Fatalf("WipeAll = %d, want 0", remaining)
	}

	after, err := processMemoryFind(m.data)
	if err != nil {
		t.Fatalf("cannot sweep process memory: %v", err)
	}
	if outside := rangesOutside(after, home); len(outside) > 0 {
		t.Errorf("the material is present in %d mapping(s) outside the needle's own mapping after WipeAll: "+
			"the sweep did not reclaim everything. First at %s", len(outside), outside[0])
	}
}

// TestWipeAll_ReturnsLockedMemoryToTheKernel measures the sweep against VmLck
// rather than the package's own bookkeeping, so a sweep that deregistered
// without unmapping fails.
func TestWipeAll_ReturnsLockedMemoryToTheKernel(t *testing.T) {
	requireCleanLedger(t)

	before, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}

	const n = 6
	for i := 0; i < n; i++ {
		if _, err := NewMemoryEnclaveSized(64); err != nil {
			t.Fatalf("NewMemoryEnclaveSized: %v", err)
		}
	}

	during, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}
	if during-before == 0 {
		t.Fatal("allocating moved VmLck by 0 bytes: the kernel is not accounting mlock, so the return-to-" +
			"baseline assertion below would be vacuous. The runner must be a real Linux kernel that reports " +
			"VmLck in /proc/self/status (see vmLckBytes)")
	}
	if want := int64(n) * LockedSize(64); during-before != want {
		t.Errorf("allocating %d enclaves locked %d bytes, want %d", n, during-before, want)
	}

	if remaining := sweep(t); remaining != 0 {
		t.Fatalf("WipeAll = %d, want 0", remaining)
	}

	after, err := vmLckBytes()
	if err != nil {
		t.Fatalf("VmLck: %v", err)
	}
	if after != before {
		t.Errorf("VmLck = %d after WipeAll, want the pre-allocation %d: the sweep marked enclaves destroyed "+
			"without returning their pages", after, before)
	}
}

// TestWipeAllAccountsAnUnwipedRelease pins that a release unmapped without a
// wipe (mprotect denied) counts as released: the enclave is deregistered, its
// reservation returned, and the condition reported as ErrReleasedWithoutWipe.
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
	protectMemory = func([]byte, protection) error { return denied }

	remaining, werr := WipeAll(context.Background())

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

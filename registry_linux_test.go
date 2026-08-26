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
	"crypto/rand"
	"io"
	"testing"
)

// TestWipeAll_LeavesNoResidentMaterial is the end-to-end property go-qrdb's exit
// path depends on: after the sweep, no material this package was holding is
// anywhere in the process's memory.
//
// It uses the corrected sweep from PR #16 — every anonymous mapping, named or
// not, with the needle held only in locked memory and compared inside a borrow.
// The earlier version of that helper skipped kernel-named mappings and would
// have reported a clean process while the material sat in [anon: Go: heap].
//
// The control comes first and is a real one: with the enclaves alive, the
// material must be findable OUTSIDE the enclave holding the needle. That proves
// the sweep can see the mappings a leak would live in, which is precisely what
// the earlier control failed to establish.
func TestWipeAll_LeavesNoResidentMaterial(t *testing.T) {
	// The needle lives in a RAW mapping, not a MemoryEnclave. Two reasons, and
	// the first is not obvious: every MemoryEnclave is on the shutdown ledger, so
	// WipeAll would destroy the needle's own holder and there would be nothing
	// left to compare against afterwards. (Measured — the first version of this
	// test did exactly that and failed reading its own needle.) The second is the
	// usual one: a []byte literal would put the needle on the heap and the sweep
	// would find the test's own constant every run.
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

	// Several registered enclaves holding the same material, so the sweep has
	// more than one place to find it and the assertion is not about a single
	// allocation.
	const copies = 4
	for i := 0; i < copies; i++ {
		tmp := make([]byte, len(m.data))
		copy(tmp, m.data)
		if _, err := NewMemoryEnclave(tmp); err != nil {
			t.Fatalf("NewMemoryEnclave: %v", err)
		}
	}

	// Control first, and a real one: with those enclaves alive the material must
	// be findable OUTSIDE the needle's own mapping. That proves the sweep can see
	// the mappings a leak would live in — which is exactly what the earlier
	// version of this control never established.
	withLive, err := processMemoryFind(m.data)
	if err != nil {
		t.Skipf("cannot sweep process memory: %v", err)
	}
	if outside := rangesOutside(withLive, home); len(outside) == 0 {
		t.Skipf("the sweep found no match outside the needle's own mapping while %d enclaves held the "+
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
// rather than against this package's own bookkeeping. An implementation that
// cleared its registry and marked everything destroyed without unmapping would
// satisfy every other assertion in this file and leave the pages locked.
func TestWipeAll_ReturnsLockedMemoryToTheKernel(t *testing.T) {
	if _, err := vmLckBytes(); err != nil {
		t.Skipf("cannot read VmLck: %v", err)
	}
	if remaining := sweep(t); remaining != 0 {
		t.Skipf("the process already holds %d unwipeable enclaves; this measurement would be noisy", remaining)
	}

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
		t.Skip("allocating moved VmLck by 0 bytes; mlock is not accounted here and this test would be vacuous")
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

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
	"errors"
	"testing"
)

// TestWipeAllAccountsAnUnwipedRelease pins that a release unmapped without a
// wipe (mprotect denied) counts as released: the enclave is deregistered, its
// reservation returned, and the condition reported as ErrReleasedWithoutWipe.
func TestWipeAllAccountsAnUnwipedRelease(t *testing.T) {
	a, err := newBudgetAllocator(1 << 20)
	if err != nil {
		t.Fatalf("NewAllocator: %v", err)
	}

	e, err := a.admitData([]byte("material the sweep must account for"))
	if err != nil {
		t.Fatalf("Allocator.New: %v", err)
	}
	if e.m.mutable {
		t.Fatal("enclave is not frozen; this test would not exercise the path")
	}

	denied := errors.New("mprotect denied by policy")
	swapSeam(t, &protectMemory, func([]byte, protection) error { return denied })

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

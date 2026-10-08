// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package enclave

import "testing"

// TestDiscoverLockedMemoryLimit_ReportsUnsupported pins that platforms with no
// locked-memory rlimit always report LimitUnsupported, the counterpart of the
// Linux and BSD tests that it is never reported there. CI is Linux-only; this
// is compiled by GOOS=windows vet.
func TestDiscoverLockedMemoryLimit_ReportsUnsupported(t *testing.T) {
	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	if limit.Source != LimitUnsupported {
		t.Fatalf("Source = %v, want LimitUnsupported on a platform with no locked-memory rlimit", limit.Source)
	}
	if limit.Bounded {
		t.Fatal("Bounded is true with no ceiling to be bounded by")
	}
	// Nothing is refused.
	a, err := NewAllocatorWithinRLimit(1 << 40)
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit refused a budget where no ceiling was read: %v", err)
	}
	if a.Limit() != 1<<40 {
		t.Fatalf("Limit = %d, want the budget asked for", a.Limit())
	}
}

// testMemlockHardLimit: no test here drops CAP_IPC_LOCK, so there is no
// hard-limit half to the requirement.
func testMemlockHardLimit() (uint64, bool) { return 0, true }

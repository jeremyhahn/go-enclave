// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package enclave

import "testing"

// TestDiscoverLockedMemoryLimit_ReportsUnsupported is the other half of the
// pair whose Linux and BSD halves live in memlock_linux_test.go and
// memlock_bsd_test.go: there, LimitUnsupported must NEVER be reported, because
// a ceiling was readable and saying otherwise would be a check that did not
// run. Here it must ALWAYS be reported, because there is genuinely nothing to
// read and claiming a ceiling would be worse than admitting none.
//
// Splitting it this way is what makes the source mean something. A single
// portable test could only assert self-consistency, which both a working
// discovery and one that never looked would satisfy.
//
// Like the BSD file, this never runs here — CI is Linux-only — and
// `GOOS=windows go vet ./...` is what checks it compiles.
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
	// And the contract that follows from it: nothing is refused.
	a, err := NewAllocatorWithinRLimit(1 << 40)
	if err != nil {
		t.Fatalf("NewAllocatorWithinRLimit refused a budget where no ceiling was read: %v", err)
	}
	if a.Limit() != 1<<40 {
		t.Fatalf("Limit = %d, want the budget asked for", a.Limit())
	}
}

// testMemlockHardLimit: no test on this platform drops CAP_IPC_LOCK to inject
// a locked-memory ceiling, so there is no hard-limit half to the requirement.
func testMemlockHardLimit() (uint64, bool) { return 0, true }

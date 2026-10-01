// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package enclave

import (
	"math"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRlimInfinityIsTheBSDSentinel pins the one platform-specific fact in
// memlock_bsd.go that the shared classifier's tests cannot reach: the sentinel
// itself.
//
// It is honest about what it is. CI here is Linux-only, so this never RUNS —
// `GOOS=darwin go vet ./...` compiles it and nothing executes it. It is
// therefore a compile-time guard plus a statement of intent for whoever first
// runs the suite on a BSD, and the classification it protects is exercised on
// every Linux run through classifyRlimit's bsdRlimInfinity cases.
func TestRlimInfinityIsTheBSDSentinel(t *testing.T) {
	if rlimInfinity != uint64(unix.RLIM_INFINITY) {
		t.Fatalf("rlimInfinity = %#x, but unix.RLIM_INFINITY = %#x", rlimInfinity, uint64(unix.RLIM_INFINITY))
	}
	// The BSD sentinel is int64's maximum, not all-bits-set. Reading one with
	// the other's value is the failure this constant exists to prevent, and it
	// is silent: a bounded ceiling of nine exabytes, or of -1.
	if rlimInfinity != uint64(math.MaxInt64) {
		t.Fatalf("rlimInfinity = %#x, want the largest positive int64 (%#x)", rlimInfinity, uint64(math.MaxInt64))
	}
	if rlimInfinity == ^uint64(0) {
		t.Fatal("rlimInfinity is the Linux sentinel; this file is built for the BSDs")
	}
}

// TestDiscoverLockedMemoryLimit_BSDReportsSomething asserts the BSD path
// answers at all, and that whatever it answers is self-consistent. It cannot
// assert a figure — that is the host's — but it can assert that this platform
// is never reported as having no discoverable limit, which is the fail-open
// this file exists to close.
func TestDiscoverLockedMemoryLimit_BSDReportsSomething(t *testing.T) {
	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		t.Fatalf("DiscoverLockedMemoryLimit: %v", err)
	}
	if limit.Source == LimitUnsupported {
		t.Fatal("a BSD reported LimitUnsupported; RLIMIT_MEMLOCK is readable here and must be read")
	}
	if limit.Source == LimitNotEnforced {
		t.Fatal("LimitNotEnforced is a Linux capability case; the BSDs claim no mlock bypass")
	}
	if limit.Bounded != (limit.Source == LimitRLimit) {
		t.Fatalf("Bounded = %v with Source = %v", limit.Bounded, limit.Source)
	}
	t.Logf("host locked-memory ceiling: bytes=%d bounded=%v source=%s", limit.Bytes, limit.Bounded, limit.Source)
}

// testMemlockHardLimit: no test on this platform drops CAP_IPC_LOCK to inject
// a locked-memory ceiling, so there is no hard-limit half to the requirement.
func testMemlockHardLimit() (uint64, bool) { return 0, true }

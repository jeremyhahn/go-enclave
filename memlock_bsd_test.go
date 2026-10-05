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

// TestRlimInfinityIsTheBSDSentinel pins rlimInfinity to the largest int64.
// CI is Linux-only, so this is compiled by GOOS=darwin vet and not run; the
// classification itself runs on Linux via the bsdRlimInfinity cases.
func TestRlimInfinityIsTheBSDSentinel(t *testing.T) {
	if rlimInfinity != uint64(unix.RLIM_INFINITY) {
		t.Fatalf("rlimInfinity = %#x, but unix.RLIM_INFINITY = %#x", rlimInfinity, uint64(unix.RLIM_INFINITY))
	}
	// int64's maximum, not all-bits-set.
	if rlimInfinity != uint64(math.MaxInt64) {
		t.Fatalf("rlimInfinity = %#x, want the largest positive int64 (%#x)", rlimInfinity, uint64(math.MaxInt64))
	}
	if rlimInfinity == ^uint64(0) {
		t.Fatal("rlimInfinity is the Linux sentinel; this file is built for the BSDs")
	}
}

// TestDiscoverLockedMemoryLimit_BSDReportsSomething pins that the BSD path
// answers, self-consistently, and never reports LimitUnsupported.
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

// testMemlockHardLimit: no test here drops CAP_IPC_LOCK, so there is no
// hard-limit half to the requirement.
func testMemlockHardLimit() (uint64, bool) { return 0, true }

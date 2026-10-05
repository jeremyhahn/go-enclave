// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// rlimInfinity is RLIM_INFINITY as Linux reports it: all bits set on every
// architecture (RLIM64_INFINITY via prlimit64). It is spelled out because
// unix.RLIM_INFINITY is untyped and per-architecture; a test asserts they agree.
const rlimInfinity = ^uint64(0)

// discoverLockedMemoryLimit reads RLIMIT_MEMLOCK and reports what it means for
// this process.
func discoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return LockedMemoryLimit{}, &LimitDiscoveryError{Cause: err}
	}
	// The soft limit is the one mlock is checked against; raising it toward the
	// hard limit is the application's business.
	return classifyRlimit(rl.Cur, rlimInfinity, memlockRLimitEnforced()), nil
}

// memlockRLimitEnforced reports whether RLIMIT_MEMLOCK binds this process's
// mlock calls. It does not when the calling thread holds CAP_IPC_LOCK
// (effective set, read with capget, not inferred from uid) in the initial user
// namespace. A capget failure or a non-initial namespace answers enforced.
// Capabilities are per-thread; a thread whose set was changed with capset can
// disagree, and the cost is a skipped refusal, not an unsafe allocation. See
// [LimitNotEnforced].
func memlockRLimitEnforced() bool {
	if !inInitialUserNamespace() {
		return true
	}

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return true
	}

	const (
		word = unix.CAP_IPC_LOCK / 32
		bit  = unix.CAP_IPC_LOCK % 32
	)
	// Only the effective set bypasses the limit.
	return data[word].Effective&(1<<bit) == 0
}

// readUIDMap returns /proc/self/uid_map; a test seam.
var readUIDMap = func() ([]byte, error) { return os.ReadFile("/proc/self/uid_map") }

// inInitialUserNamespace reports whether this process runs in the initial user
// namespace, the only one whose CAP_IPC_LOCK lifts RLIMIT_MEMLOCK. It matches
// the identity map "0 0 4294967295"; an unreadable map answers false. A child
// namespace given the same full map is indistinguishable and reads as initial.
func inInitialUserNamespace() bool {
	m, err := readUIDMap()
	if err != nil {
		return false
	}
	return isInitialUIDMap(m)
}

// isInitialUIDMap reports whether m is exactly one uid_map line mapping the
// full uid range onto itself.
func isInitialUIDMap(m []byte) bool {
	f := strings.Fields(string(m))
	return len(f) == 3 && f[0] == "0" && f[1] == "0" && f[2] == "4294967295"
}

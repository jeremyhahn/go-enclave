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

// memlockRLimitEnforced reports whether RLIMIT_MEMLOCK binds this process's mlock calls.
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

// inInitialUserNamespace reports whether this process runs in the initial user namespace.
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

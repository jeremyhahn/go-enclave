// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

package enclave

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// rlimInfinity is RLIM_INFINITY as it appears in a struct rlimit read back from
// the Linux kernel: all bits set.
//
// It is spelled here rather than taken from unix.RLIM_INFINITY because that
// constant is untyped and generated per-architecture, and the comparison it
// feeds has to be against a uint64 on every one of them. The value itself is
// fixed by the kernel ABI — Linux reports RLIM64_INFINITY from the prlimit64
// path that x/sys uses on 32-bit as well as 64-bit — so this is not a guess; a
// unit test asserts it against unix.RLIM_INFINITY. The BSDs use a different
// value, which is why [classifyRlimit] takes it as an argument rather than
// reading a package-level constant.
const rlimInfinity = ^uint64(0)

// discoverLockedMemoryLimit reads RLIMIT_MEMLOCK and reports what it means for
// this process.
func discoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return LockedMemoryLimit{}, &LimitDiscoveryError{Cause: err}
	}
	// The SOFT limit is the one that binds. The hard limit is only a ceiling on
	// what the process may raise the soft one to, and raising it is the
	// application's business, not this package's.
	return classifyRlimit(rl.Cur, rlimInfinity, memlockRLimitEnforced()), nil
}

// memlockRLimitEnforced reports whether RLIMIT_MEMLOCK actually binds this
// process's mlock calls.
//
// It does not, for a process holding CAP_IPC_LOCK: since Linux 2.6.9 that
// capability lets mlock exceed the limit outright, so the number read from
// getrlimit describes a rule the kernel will not apply. Assuming the soft limit
// binds is therefore wrong for exactly the deployments most likely to raise it
// — privileged containers, services started as root — and wrong in the
// direction that breaks them at startup.
//
// The capability is read with capget rather than by testing for uid 0. Root can
// have dropped CAP_IPC_LOCK and a non-root process can have been granted it via
// file capabilities or an ambient set, so uid answers a different question than
// the one being asked.
//
// A capget failure is treated as ENFORCED. That is the safe direction here even
// though it risks a false refusal: capget has existed since 2.6.26 and is not
// something a working host fails, whereas assuming the capability on any error
// would silently disable this whole check for every process on a host where
// capget happened to be filtered — a guard that reports fine and is not
// looking.
//
// The capability only counts in the INITIAL user namespace: the kernel checks
// CAP_IPC_LOCK against it, so a rootless container's root holds the capability
// in its own namespace and is still bound by the limit. See
// [inInitialUserNamespace].
//
// It answers for the CALLING THREAD, because that is the only question Linux
// has an answer to: capabilities are per-thread and there is no process-wide
// set to read. In practice the threads of a Go program agree — a thread
// inherits its creator's capabilities and only a deliberate capset, normally
// under runtime.LockOSThread, diverges them — but where they do not, a
// constructor called on a privileged thread reports the limit unenforced while
// an allocation later runs on a thread the limit binds. The cost of that is a
// SKIPPED refusal: the allocation fails with ErrLockedMemoryUnavailable exactly
// as it did before this check existed. Nothing is made unsafe, and the
// alternative reading — refuse anyway — breaks a privileged service that is
// configured correctly. See [LimitNotEnforced].
func memlockRLimitEnforced() bool {
	if !inInitialUserNamespace() {
		return true
	}

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return true
	}

	// Capabilities are a bitmap split across 32-bit words; CAP_IPC_LOCK is 14,
	// so it lives in the low word. Deriving the index rather than writing 0
	// keeps this correct if it is ever copied for a capability above 31.
	const (
		word = unix.CAP_IPC_LOCK / 32
		bit  = unix.CAP_IPC_LOCK % 32
	)
	// The EFFECTIVE set is what the kernel checks at the moment of the mlock;
	// permitted-but-not-effective does not bypass the limit.
	return data[word].Effective&(1<<bit) == 0
}

// readUIDMap returns /proc/self/uid_map. A seam so tests can present any
// namespace without creating one.
var readUIDMap = func() ([]byte, error) { return os.ReadFile("/proc/self/uid_map") }

// inInitialUserNamespace reports whether this process runs in the initial user
// namespace, the only one whose CAP_IPC_LOCK lifts RLIMIT_MEMLOCK.
//
// The initial namespace's uid_map is the identity map of the whole uid range,
// "0 0 4294967295". An unreadable map answers false, so the limit is treated as
// enforced. A child namespace given that same full identity map, which only a
// process privileged in the parent can create, is indistinguishable here and
// is reported as initial.
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

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package enclave

import (
	"math"

	"golang.org/x/sys/unix"
)

// Linux and the BSDs read the same rlimit; memlock_linux.go and memlock_bsd.go
// state what differs: the RLIM_INFINITY sentinel (rlimInfinity) and whether the
// limit binds (memlockRLimitEnforced).

// DiscoverLockedMemoryLimit reads the soft RLIMIT_MEMLOCK and what it means for this process; [ErrLockedMemoryUnavailable] stays the authority.
func DiscoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return LockedMemoryLimit{}, &LimitDiscoveryError{Cause: err}
	}
	return classifyRlimit(rlimitUint64(rl.Cur), rlimInfinity, memlockRLimitEnforced()), nil
}

// rlimitUint64 widens an rlimit field to uint64; a negative value maps to MaxUint64.
func rlimitUint64[T int64 | uint64](v T) uint64 {
	if v < 0 {
		return math.MaxUint64
	}
	return uint64(v)
}

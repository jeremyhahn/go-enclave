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

// DiscoverLockedMemoryLimit reads the process's current locked-memory ceiling:
// the soft RLIMIT_MEMLOCK, the one mlock is checked against, and what it means
// for this process. Raising it toward the hard limit is the application's
// business.
//
// Use it to derive a budget from the host rather than guess one:
//
//	limit, err := enclave.DiscoverLockedMemoryLimit()
//	switch {
//	case err != nil:
//		return err
//	case limit.Bounded:
//		budget = limit.Bytes / 2 // leave the other half for everything else
//	default:
//		budget = cfg.LockedBudget // nothing bounds us; the config decides
//		log.Printf("locked-memory budget %d from config (%s)", budget, limit.Source)
//	}
//
// The error is [ErrLimitDiscoveryFailed], as a [LimitDiscoveryError] wrapping
// the syscall. An unbounded ceiling, or a platform that exposes none, is not an
// error: it returns Bounded false and a [LimitSource] saying which.
//
// The figure is an upper bound on what may be assumed, not a guarantee: other
// code in the process locks against the same ceiling, a cgroup v2 memory.max
// may bind well below it (this package does not read cgroup state), and the
// limit can move after it is read.
//
// [ErrLockedMemoryUnavailable] remains the only authority on what this process
// may actually lock, and callers must still handle it.
func DiscoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return LockedMemoryLimit{}, &LimitDiscoveryError{Cause: err}
	}
	return classifyRlimit(rlimitUint64(rl.Cur), rlimInfinity, memlockRLimitEnforced()), nil
}

// rlimitUint64 widens an rlimit field to uint64 whichever its signedness: it is
// signed on FreeBSD and DragonFly and unsigned elsewhere. A negative value has
// no meaning as a byte count and maps to MaxUint64, which classifyRlimit reads
// as unbounded.
func rlimitUint64[T int64 | uint64](v T) uint64 {
	if v < 0 {
		return math.MaxUint64
	}
	return uint64(v)
}

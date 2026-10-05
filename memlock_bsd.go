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

	"golang.org/x/sys/unix"
)

// rlimInfinity is RLIM_INFINITY on the BSDs: the largest int64, not Linux's
// all-bits-set. A test pins its conversion to uint64.
const rlimInfinity = uint64(unix.RLIM_INFINITY)

// discoverLockedMemoryLimit reads the soft RLIMIT_MEMLOCK and reports it as
// enforced: the BSDs have no CAP_IPC_LOCK to bypass it. Darwin in practice
// reports RLIM_INFINITY, which classifies as unlimited. CI runs Linux only, so
// this path is not exercised on a real BSD; classifyRlimit is shared with Linux
// and unit-tested against both sentinels.
func discoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return LockedMemoryLimit{}, &LimitDiscoveryError{Cause: err}
	}
	// The field is signed on FreeBSD and DragonFly and unsigned elsewhere.
	return classifyRlimit(rlimitUint64(rl.Cur), rlimInfinity, true), nil
}

// rlimitUint64 widens an rlimit field to uint64 whichever its signedness. A
// negative value has no meaning as a byte count and maps to MaxUint64, which
// classifyRlimit reads as unbounded.
func rlimitUint64[T int64 | uint64](v T) uint64 {
	if v < 0 {
		return math.MaxUint64
	}
	return uint64(v)
}

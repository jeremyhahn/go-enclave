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

// rlimInfinity is RLIM_INFINITY on the BSDs, which is NOT the Linux value: they
// use the largest positive value of a signed 64-bit quantity rather than
// all-bits-set. Getting that wrong is not a cosmetic difference — an unlimited
// ceiling read against the wrong sentinel classifies as a bounded ceiling of
// about 9 exabytes, which happens to refuse nothing, or as a bounded ceiling of
// -1, which refuses everything.
//
// It comes from unix.RLIM_INFINITY rather than being spelled out, because
// unlike the Linux constant this one converts cleanly to uint64 on every one of
// these platforms; a test in memlock_bsd_test.go pins the conversion.
const rlimInfinity = uint64(unix.RLIM_INFINITY)

// discoverLockedMemoryLimit reads RLIMIT_MEMLOCK on the BSDs, which all define
// it.
//
// # What this path is and is not
//
// It exists because the alternative was worse. Reporting [LimitUnsupported] on
// a platform that DOES expose a locked-memory ceiling is a fail-open guard: the
// budget was checkable, the constructor said nothing, and the failure lands
// later under allocation pressure — the exact shape this API exists to remove.
// Hosted review blocked the branch over it, correctly.
//
// It is nonetheless the least verified code in this package: the repository's
// CI is Linux-only, so nothing here is exercised on a real BSD. Two things
// bound the risk. The classification — every reading of the raw number,
// including RLIM_INFINITY and the unenforced case — is [classifyRlimit], which
// is shared with Linux and unit-tested against BOTH sentinel values, so only
// the syscall and the constant above are untested. And the failure mode of a
// mistake here is a REFUSAL at startup, which is loud and names its figures,
// rather than something that goes wrong quietly later.
//
// The rlimit is reported as ENFORCED. The BSDs have no CAP_IPC_LOCK, so there
// is no capability to consult, and no bypass is claimed on their behalf; the
// soft limit is what mlock is checked against. Darwin in practice reports
// RLIM_INFINITY here, which classifies as unlimited and refuses nothing.
func discoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return LockedMemoryLimit{}, &LimitDiscoveryError{Cause: err}
	}
	// The field is signed on FreeBSD and DragonFly and unsigned on Darwin,
	// NetBSD and OpenBSD, so it is widened through rlimitUint64 rather than a
	// bare conversion. classifyRlimit takes the widest form and handles
	// everything at or beyond int64 as unbounded, so a value that arrives out of
	// range is refused nothing rather than truncated into a small ceiling.
	return classifyRlimit(rlimitUint64(rl.Cur), rlimInfinity, true), nil
}

// rlimitUint64 widens an rlimit field to uint64 whichever signedness the
// platform gives it. A NEGATIVE signed value has no meaning as a byte count —
// no kernel reports one — so it is mapped deliberately to the top of the range,
// which classifyRlimit reads as unbounded: the same answer a wrapped
// conversion would have produced by accident, now stated rather than implied.
func rlimitUint64[T int64 | uint64](v T) uint64 {
	if v < 0 {
		return math.MaxUint64
	}
	return uint64(v)
}

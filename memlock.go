// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "math"

// LimitSource names where a discovered locked-memory ceiling came from, or why
// there is none, so a caller can log how its budget was derived and not only
// the number.
type LimitSource uint8

const (
	// LimitUnknown is the zero value. It appears only in the zero
	// [LockedMemoryLimit] returned alongside an error.
	LimitUnknown LimitSource = iota

	// LimitRLimit means a finite RLIMIT_MEMLOCK soft limit binds this process.
	// It is the only source for which [LockedMemoryLimit.Bounded] is true.
	LimitRLimit

	// LimitUnlimited means RLIMIT_MEMLOCK is RLIM_INFINITY (or exceeds any
	// int64 budget), as under `ulimit -l unlimited` and in many container
	// runtimes. No budget is refused, but machine memory and cgroup limits
	// still apply: the budget has to come from configuration.
	LimitUnlimited

	// LimitNotEnforced means a finite RLIMIT_MEMLOCK was read, but the calling
	// thread holds CAP_IPC_LOCK in the initial user namespace, so mlock may
	// exceed it. The capability held only inside a child user namespace (a
	// rootless container) reports [LimitRLimit]. The figure is in
	// [LockedMemoryLimit.Bytes] for diagnostics and is never a ceiling.
	// Capabilities are per-thread on Linux; if threads diverge, the effect is a
	// skipped refusal and the allocation still fails with
	// [ErrLockedMemoryUnavailable].
	LimitNotEnforced

	// LimitUnsupported means the platform exposes no per-process
	// locked-memory limit: Windows (which bounds a working-set size instead),
	// AIX, Solaris and illumos. Unlike [LimitUnlimited] it says nothing was
	// read, not that the host has no ceiling. Linux and the BSDs are always read.
	LimitUnsupported
)

// String implements fmt.Stringer.
func (s LimitSource) String() string {
	switch s {
	case LimitRLimit:
		return "RLIMIT_MEMLOCK"
	case LimitUnlimited:
		return "RLIMIT_MEMLOCK unlimited"
	case LimitNotEnforced:
		return "RLIMIT_MEMLOCK not enforced (CAP_IPC_LOCK)"
	case LimitUnsupported:
		return "no locked-memory limit on this platform"
	default:
		return "unknown"
	}
}

// LockedMemoryLimit is a snapshot of the process's locked-memory ceiling, taken
// by [DiscoverLockedMemoryLimit]. Any thread may change RLIMIT_MEMLOCK and a
// container may be resized afterwards, so it describes the moment it was read.
type LockedMemoryLimit struct {
	// Bytes is the ceiling the kernel reported, in bytes. Rely on it only when
	// Bounded is true: it is populated for [LimitNotEnforced] and zero when
	// there was nothing to read, so a zero never means "may lock nothing"
	// unless Bounded.
	Bytes int64

	// Bounded reports whether Bytes is a ceiling this process is held to.
	Bounded bool

	// Source records where the figure came from, or why there is none.
	Source LimitSource
}

// refuse returns the *RLimitError a budget of maxBytes earns against this
// ceiling, or nil. Only a bounded ceiling refuses. It is a method so tests reach
// every comparison on any host without injecting a ceiling.
func (l LockedMemoryLimit) refuse(maxBytes int64) error {
	if l.Bounded && maxBytes > l.Bytes {
		return &RLimitError{Requested: maxBytes, Limit: l}
	}
	return nil
}

// classifyRlimit turns a raw RLIMIT_MEMLOCK soft value into a
// LockedMemoryLimit. It takes the platform's RLIM_INFINITY because Linux and
// the BSDs disagree on it, and it is separate from the syscall so every case
// is unit-testable without privilege or a BSD host.
func classifyRlimit(cur, infinity uint64, enforced bool) LockedMemoryLimit {
	// Checked first: Linux's RLIM_INFINITY as an int64 is -1, which would
	// refuse every budget.
	if cur == infinity {
		return LockedMemoryLimit{Source: LimitUnlimited}
	}

	// No int64 budget can exceed a ceiling past MaxInt64, and truncating it
	// would invent a small one. A negative BSD rlimit lands here too.
	if cur > uint64(math.MaxInt64) {
		return LockedMemoryLimit{Source: LimitUnlimited}
	}

	limit := int64(cur)

	if !enforced {
		return LockedMemoryLimit{Bytes: limit, Source: LimitNotEnforced}
	}

	// Zero is a bounded ceiling of zero bytes: every positive budget is refused.
	return LockedMemoryLimit{Bytes: limit, Bounded: true, Source: LimitRLimit}
}

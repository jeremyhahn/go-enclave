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

	// LimitUnlimited means RLIMIT_MEMLOCK is unbounded; the budget must come from configuration.
	LimitUnlimited

	// LimitNotEnforced means a finite limit was read but CAP_IPC_LOCK in the initial user namespace lifts it.
	LimitNotEnforced

	// LimitUnsupported means the platform exposes no per-process locked-memory limit.
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
	// Bytes is the ceiling the kernel reported; rely on it only when Bounded is true.
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

// classifyRlimit turns a raw RLIMIT_MEMLOCK soft value into a LockedMemoryLimit.
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

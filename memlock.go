// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"errors"
	"fmt"
	"math"
)

// ErrBudgetExceedsRLimit is returned by [NewAllocatorWithinRLimit],
// [Allocator.SetLimit] and [Allocator.TransferTo] when a budget is larger than
// the locked memory this process may hold. Every [RLimitError] matches it.
//
// It differs from [ErrInvalidBudget] (a non-positive budget, checked before the
// ceiling is read), [ErrBudgetExhausted] (a live allocator's own budget is
// full) and [ErrLockedMemoryUnavailable] (the kernel refused to lock pages; the
// authority on what may be locked, where this reports only what the ceiling
// said when read).
var ErrBudgetExceedsRLimit = errors.New("enclave: allocator budget exceeds the process's locked-memory limit")

// ErrLimitDiscoveryFailed reports that the ceiling could not be read (a
// getrlimit that did not answer). Every [LimitDiscoveryError] matches it.
// Nothing was compared, so it is neither a budget problem nor a shortage; a
// caller that can proceed may fall back to [NewAllocator] with a configured
// budget and log that the budget went unchecked.
var ErrLimitDiscoveryFailed = errors.New("enclave: could not read the process's locked-memory limit")

// LimitDiscoveryError reports that the process's locked-memory ceiling could
// not be read. Match on [ErrLimitDiscoveryFailed]; Unwrap reaches the syscall
// failure, which is diagnostic rather than contract.
type LimitDiscoveryError struct {
	// Cause is the getrlimit failure; never nil in an error this package
	// constructs.
	Cause error
}

// Error implements error.
func (e *LimitDiscoveryError) Error() string {
	if e.Cause == nil {
		return ErrLimitDiscoveryFailed.Error()
	}
	return ErrLimitDiscoveryFailed.Error() + ": " + e.Cause.Error()
}

// Is reports every LimitDiscoveryError as [ErrLimitDiscoveryFailed].
func (e *LimitDiscoveryError) Is(target error) bool {
	return target == ErrLimitDiscoveryFailed
}

// Unwrap returns the syscall failure.
func (e *LimitDiscoveryError) Unwrap() error { return e.Cause }

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

// RLimitError reports that an [Allocator] budget was refused because it exceeds
// the locked memory the process may hold, carrying both figures. Match on
// [ErrBudgetExceedsRLimit].
type RLimitError struct {
	// Requested is the budget the caller asked for, in locked bytes.
	Requested int64
	// Limit is the ceiling as discovered; Limit.Bounded is always true.
	Limit LockedMemoryLimit
}

// Error implements error.
func (e *RLimitError) Error() string {
	return fmt.Sprintf("%s: %d bytes requested, %s is %d bytes",
		ErrBudgetExceedsRLimit.Error(), e.Requested, e.Limit.Source, e.Limit.Bytes)
}

// Is reports every RLimitError as [ErrBudgetExceedsRLimit].
func (e *RLimitError) Is(target error) bool {
	return target == ErrBudgetExceedsRLimit
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

// DiscoverLockedMemoryLimit reads the process's current locked-memory ceiling.
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
	return discoverLockedMemoryLimit()
}

// NewAllocatorWithinRLimit is [NewAllocator] with a ceiling check: it discovers
// the process's locked-memory ceiling and refuses a budget that exceeds it,
// naming both figures. Prefer it for a budget that comes from configuration, so
// an unsatisfiable budget fails at startup rather than under load. It never
// exits, logs or panics; acting on the error is the application's choice.
//
// It returns:
//   - [ErrInvalidBudget] when maxBytes is not positive, checked before any
//     syscall.
//   - [ErrBudgetExceedsRLimit] (as an [RLimitError]) when the ceiling is
//     bounded and maxBytes is above it.
//   - [ErrLimitDiscoveryFailed] (as a [LimitDiscoveryError]) if the ceiling
//     could not be read.
//
// Otherwise it returns what [NewAllocator] would. Size the budget in pages and
// leave headroom: a budget equal to the ceiling passes and leaves nothing for
// the rest of the process. Passing does not promise allocations will succeed
// (see [DiscoverLockedMemoryLimit]); the ceiling is not re-read on admission,
// and the kernel's refusal is still reported as [ErrLockedMemoryUnavailable].
//
// The check is sticky: [Allocator.SetLimit] re-reads the ceiling and refuses to
// raise this allocator's budget above it, and [Allocator.TransferTo] does the
// same for the allocator it credits, both with [ErrBudgetExceedsRLimit].
// Lowering is never checked; [Allocator.ForceLimit] is the deliberate override.
func NewAllocatorWithinRLimit(maxBytes int64) (*Allocator, error) {
	if maxBytes <= 0 {
		return nil, ErrInvalidBudget
	}

	limit, err := DiscoverLockedMemoryLimit()
	if err != nil {
		return nil, err
	}

	if err := limit.refuse(maxBytes); err != nil {
		return nil, err
	}

	// true makes the ceiling check apply to later SetLimit and TransferTo.
	return newAllocator(maxBytes, true)
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

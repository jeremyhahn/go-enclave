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

// ErrBudgetExceedsRLimit is the sentinel returned by
// [NewAllocatorWithinRLimit] when the requested budget is larger than the
// locked memory this process is allowed to hold. Every [RLimitError] matches
// it, so this is what callers test for.
//
// It is deliberately distinct from the three errors it sits between:
//
//   - [ErrInvalidBudget] reports a budget that is wrong on every host — zero or
//     negative — and is returned BEFORE the ceiling is read, so a nonsense
//     budget never reports as a host-configuration problem.
//   - [ErrBudgetExhausted] reports a live allocator refusing one allocation
//     because its own budget is full. This one reports a budget that was never
//     satisfiable in the first place, and is returned instead of an allocator.
//   - [ErrLockedMemoryUnavailable] reports the kernel actually refusing to lock
//     pages. That is the authority on what this process may lock; this sentinel
//     only reports what the ceiling SAID at construction time.
var ErrBudgetExceedsRLimit = errors.New("enclave: allocator budget exceeds the process's locked-memory limit")

// ErrLimitDiscoveryFailed is the sentinel for a failure to READ the ceiling —
// a getrlimit that did not answer. Every [LimitDiscoveryError] matches it.
//
// It reports neither a budget problem nor a locked-memory shortage: nothing was
// compared, because nothing was learned. A caller that cannot proceed without
// the reading should treat it as fatal to its own startup; one that can should
// fall back to [NewAllocator] with a configured budget and say in its log that
// the budget went unchecked.
var ErrLimitDiscoveryFailed = errors.New("enclave: could not read the process's locked-memory limit")

// LimitDiscoveryError reports that the process's locked-memory ceiling could
// not be read.
//
// It carries the syscall failure, which is the only thing that distinguishes
// one cause from another — a filtered getrlimit, a sandbox — and that detail is
// diagnostic rather than contract. Match on [ErrLimitDiscoveryFailed];
// errors.Is reports it for every LimitDiscoveryError, and errors.As or
// errors.Unwrap reaches the cause.
type LimitDiscoveryError struct {
	// Cause is the underlying getrlimit failure. It is never nil in an error
	// this package constructs.
	Cause error
}

// Error implements error.
func (e *LimitDiscoveryError) Error() string {
	if e.Cause == nil {
		return ErrLimitDiscoveryFailed.Error()
	}
	return ErrLimitDiscoveryFailed.Error() + ": " + e.Cause.Error()
}

// Is reports every LimitDiscoveryError as ErrLimitDiscoveryFailed, so callers
// match the sentinel and never have to know about this type.
func (e *LimitDiscoveryError) Is(target error) bool {
	return target == ErrLimitDiscoveryFailed
}

// Unwrap returns the syscall failure, so errors.As can reach it.
func (e *LimitDiscoveryError) Unwrap() error { return e.Cause }

// LimitSource names where a discovered locked-memory ceiling came from — or why
// there is no ceiling to report.
//
// It exists so a caller can record the DERIVATION of the budget it settled on
// and not only the number. "8 MiB, because RLIMIT_MEMLOCK said so" and "8 MiB,
// because nothing bounded us and this is what the config file asked for" are
// the same figure and completely different facts, and the second is the one an
// operator wants when the process later runs out.
type LimitSource uint8

const (
	// LimitUnknown is the zero value and names no source. It appears only in
	// the zero [LockedMemoryLimit], which is what discovery returns alongside
	// an error; a successful discovery never reports it.
	LimitUnknown LimitSource = iota

	// LimitRLimit means a finite RLIMIT_MEMLOCK soft limit was read and it
	// binds this process. This is the only source for which
	// [LockedMemoryLimit.Bounded] is true.
	LimitRLimit

	// LimitUnlimited means RLIMIT_MEMLOCK is RLIM_INFINITY — the norm under
	// `ulimit -l unlimited` and in many container runtimes. There is no ceiling
	// to compare a budget against, so no budget is refused for exceeding it.
	//
	// This is NOT a license to size a budget freely: the machine still has a
	// finite amount of memory, and cgroup limits still apply (see
	// [DiscoverLockedMemoryLimit]). It means the budget has to come from
	// configuration, because the host is not supplying one.
	LimitUnlimited

	// LimitNotEnforced means a finite RLIMIT_MEMLOCK was read but CAP_IPC_LOCK
	// is held, which lets mlock exceed it. The figure is reported in
	// [LockedMemoryLimit.Bytes] for diagnostics and is not treated as a ceiling:
	// refusing a budget on a limit the kernel will not enforce would fail a
	// correctly configured privileged service at startup over a number that
	// does not bind it.
	//
	// Capabilities on Linux are per-THREAD, and this is the capability state of
	// the thread that called. There is no process-wide answer to read — the
	// kernel does not keep one — and in almost every program the threads agree,
	// since a new thread inherits the creator's set and only a deliberate
	// capset diverges them. Where they do diverge, this source reports the
	// calling thread and the effect is that a refusal is SKIPPED, leaving the
	// late, typed [ErrLockedMemoryUnavailable] that allocation has always
	// returned. That is the direction to be wrong in: the alternative — refusing
	// against a limit the kernel may not apply — fails a working deployment at
	// startup.
	LimitNotEnforced

	// LimitUnsupported means the platform exposes no per-process locked-memory
	// limit to read — Windows, which bounds a working-set size instead, and the
	// GOOS values that define no RLIMIT_MEMLOCK. It is NOT reported for a
	// platform that has one: Linux and the five BSDs are all read. See
	// memlock_other.go for what that path promises.
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
// by [DiscoverLockedMemoryLimit].
//
// A snapshot is all it can be: RLIMIT_MEMLOCK can be changed by a setrlimit
// from any thread in the process, and a container can be resized underneath it.
// Treat it as a fact about the moment it was read.
type LockedMemoryLimit struct {
	// Bytes is the ceiling the kernel reported, in bytes — the same unit an
	// [Allocator] budget is expressed in, which is what makes the two
	// comparable at all.
	//
	// It is a ceiling to rely on ONLY when Bounded is true. It is still
	// populated when Source is [LimitNotEnforced], because the figure is worth
	// logging even where it does not bind, and it is zero when there was no
	// figure to read at all. A zero Bytes therefore never means "this process
	// may lock nothing"; check Bounded first, always.
	Bytes int64

	// Bounded reports whether Bytes is a ceiling this process is actually held
	// to. When it is false there is nothing to compare a budget against, and a
	// budget must come from configuration instead.
	Bounded bool

	// Source records where the figure came from, or why there is none.
	Source LimitSource
}

// RLimitError reports that an [Allocator] budget was refused because it exceeds
// the locked memory the process is allowed to hold.
//
// It carries both figures so an operator can see the gap without reproducing
// the discovery by hand — the point of failing at startup is to say what to
// change. Match on [ErrBudgetExceedsRLimit]; errors.Is reports it for every
// RLimitError.
type RLimitError struct {
	// Requested is the budget the caller asked for, in locked bytes.
	Requested int64
	// Limit is the ceiling as discovered, including its source. Limit.Bounded
	// is always true here: an unbounded ceiling refuses nothing.
	Limit LockedMemoryLimit
}

// Error implements error.
func (e *RLimitError) Error() string {
	return fmt.Sprintf("%s: %d bytes requested, %s is %d bytes",
		ErrBudgetExceedsRLimit.Error(), e.Requested, e.Limit.Source, e.Limit.Bytes)
}

// Is reports every RLimitError as ErrBudgetExceedsRLimit, so callers match the
// sentinel and never have to know about this type.
func (e *RLimitError) Is(target error) bool {
	return target == ErrBudgetExceedsRLimit
}

// refuse reports the refusal a budget of maxBytes earns against this ceiling,
// and nil when there is none. It is the whole decision [NewAllocatorWithinRLimit]
// makes, and it is a method rather than four lines inside that constructor for
// a testing reason: the constructor discovers its own ceiling, so on a host
// whose ceiling cannot be injected — one holding CAP_IPC_LOCK, say — there is
// no way to reach the interesting comparisons through it. Here they are reached
// on any host, with no privilege and nothing injected.
//
// Only a ceiling that BINDS refuses anything. Unlimited, unenforced and
// absent-on-this-platform ceilings all return nil: there is no number to be
// above, and refusing on the absence of one would fail hosts that are
// configured correctly. A ceiling that could not be READ never reaches here —
// that is [ErrLimitDiscoveryFailed], reported by discovery before any
// comparison is attempted.
func (l LockedMemoryLimit) refuse(maxBytes int64) error {
	if l.Bounded && maxBytes > l.Bytes {
		return &RLimitError{Requested: maxBytes, Limit: l}
	}
	return nil
}

// DiscoverLockedMemoryLimit reads the process's current locked-memory ceiling.
//
// Use it to DERIVE a budget from the host rather than guessing one — the
// derivation an operator can then be shown:
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
// The error is a failure of the discovery itself — a getrlimit that did not
// answer — and is [ErrLimitDiscoveryFailed], as a [LimitDiscoveryError] wrapping
// the syscall. Not being ABLE to read the ceiling and there BEING no ceiling are
// different answers and must not be conflated: an unbounded ceiling, or a
// platform that exposes none, is not an error at all and comes back as a
// [LockedMemoryLimit] with Bounded false and a [LimitSource] saying which.
//
// # What this figure does not tell you
//
// It is an upper bound on what may be ASSUMED, never a guarantee. Three things
// sit outside it, and all three are why a successful check here does not
// promise that any particular allocation will succeed:
//
//   - Everything else in the process locks memory against the same ceiling —
//     another Allocator, a direct [NewMemoryEnclave], any library using mlock.
//   - Under cgroup v2 a container's memory.max frequently binds well below the
//     rlimit, and the rlimit is then close to meaningless. This package does
//     not read cgroup state: memory.max caps total memory rather than locked
//     memory specifically, so deriving a locked-memory ceiling from it would be
//     inventing a number, and inventing one is what this function exists to
//     stop.
//   - The limit can move after it is read.
//
// [ErrLockedMemoryUnavailable] remains the only authority on what this process
// may actually lock, and callers must still handle it.
func DiscoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	return discoverLockedMemoryLimit()
}

// NewAllocatorWithinRLimit is [NewAllocator] with a ceiling check that STICKS: it discovers
// the process's locked-memory ceiling and REFUSES a budget that exceeds it,
// naming the discovered figure in the error.
//
// It is the constructor to prefer for a budget that comes from configuration.
// A service whose pre-auth buffer budget was never satisfiable should learn
// that while it is starting, from an error that names both numbers, rather than
// at peak load from an allocation failure several layers away from the setting
// that caused it.
//
// Failing closed here is deliberate. The alternative — warning and continuing —
// reproduces exactly the pattern this package exists to remove: a guard that
// reports the problem somewhere that nobody correlates with the failure it
// later causes. So this is a constructor error, and it is the APPLICATION's to
// act on: a library must never os.Exit, log.Fatal or panic over a host's
// resource configuration, and this one does not.
//
// It returns:
//   - [ErrInvalidBudget] when maxBytes is not positive. That is checked FIRST,
//     before any syscall: a budget that is wrong on every host must not report
//     as a host-configuration problem.
//   - [ErrBudgetExceedsRLimit] (as an [RLimitError]) when the ceiling is
//     bounded and maxBytes is above it.
//   - [ErrLimitDiscoveryFailed] (as a [LimitDiscoveryError]) if the ceiling
//     could not be read at all. Nothing was compared, so this is neither a
//     verdict on the budget nor a shortage of locked memory.
//
// Otherwise it returns exactly what [NewAllocator] would, with the same budget
// and the same behavior afterwards. Read that constructor's guidance on sizing
// a budget in PAGES and on leaving headroom; a budget EQUAL to the ceiling
// passes this check and still leaves nothing for the rest of the process.
//
// # What the check does not promise
//
// It is one-sided, and both sides are worth stating. Passing does not promise
// allocations will succeed: the ceiling is process-wide and shared, a cgroup
// may bind below it, and it can move afterwards — see
// [DiscoverLockedMemoryLimit]. Passing on a host with no discoverable ceiling
// promises even less, since there was nothing to check against.
//
// The ceiling is never read on the ADMISSION path. Re-reading it per allocation
// would put a syscall on a path that is currently one atomic compare-and-swap,
// and it would buy nothing: a check cannot prevent a lock failure, and the
// kernel's refusal is already reported as a typed [ErrLockedMemoryUnavailable]
// by the allocation that hit it.
//
// # The check is sticky
//
// An allocator returned by this constructor carries the contract for life, and
// that is the difference between it and [NewAllocator] after construction as
// well as during it. [Allocator.SetLimit] re-reads the ceiling — freshly, since
// it moves — and refuses to raise this allocator's budget above it;
// [Allocator.TransferTo] does the same for the allocator it credits. Both
// report [ErrBudgetExceedsRLimit], the same sentinel this constructor uses.
//
// Without that, the check bound a budget for exactly as long as it took to call
// SetLimit, and two entry points to one allocator disagreed about whether the
// kernel ceiling applied (issue #46). Lowering is never checked, and
// [Allocator.ForceLimit] is the deliberate override; see those methods.
func NewAllocatorWithinRLimit(maxBytes int64) (*Allocator, error) {
	// Before the syscall, and before anything can turn this into a story about
	// the host: a non-positive budget is a caller mistake on every platform.
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

	// One construction path, so this constructor cannot drift from the other's
	// validation or its zero-value contract. The flag is what makes the check
	// above outlive this call: see [Allocator.SetLimit].
	return newAllocator(maxBytes, true)
}

// classifyRlimit turns a raw RLIMIT_MEMLOCK soft value into a
// [LockedMemoryLimit], and is where every "this number does not mean what it
// looks like" case is handled.
//
// It is shared by Linux and the BSDs, and it takes the platform's RLIM_INFINITY
// as an argument because they do not agree on it: Linux uses all-bits-set, the
// BSDs the largest positive int64. A package-level constant would silently give
// one family the other's sentinel.
//
// It is separate from the syscall on purpose, and that is what makes the BSD
// path testable at all. The interesting inputs — either RLIM_INFINITY, a value
// past int64, an unenforced limit — cannot be produced by setrlimit from an
// unprivileged test process, and CI here runs only on Linux; a classification
// reachable only on a host configured just so is a classification that goes
// untested.
func classifyRlimit(cur, infinity uint64, enforced bool) LockedMemoryLimit {
	// RLIM_INFINITY IS CHECKED EXPLICITLY, AND FIRST. Any arithmetic treatment
	// of it is wrong in a different way depending on the type it lands in: the
	// Linux value as an int64 is -1, which compares BELOW every budget and would
	// refuse them all; converted or truncated it becomes some other number that
	// is not a ceiling either. "Unlimited" is common — `ulimit -l unlimited`,
	// most container runtimes, Darwin by default — so this is the mainstream
	// case, not an edge one, and it must never read as "zero" or as "tiny".
	if cur == infinity {
		return LockedMemoryLimit{Source: LimitUnlimited}
	}

	// A finite limit too large for an int64 is reported the same way, and for
	// the same reason rather than by analogy: an Allocator budget IS an int64,
	// so no budget this package can express could exceed such a ceiling. There
	// is nothing to compare and nothing to refuse. Reporting it as a bounded
	// int64 would require truncating it, which invents a small ceiling out of an
	// enormous one. This is also where a negative value from one of the BSDs'
	// signed rlimit fields lands, since the conversion makes it enormous.
	if cur > uint64(math.MaxInt64) {
		return LockedMemoryLimit{Source: LimitUnlimited}
	}

	limit := int64(cur)

	// A limit the kernel will not hold this process to is a diagnostic, not a
	// ceiling. Refusing a budget above it would fail a privileged service at
	// startup over a number that does not bind it — the false refusal being
	// strictly worse than the late failure this check exists to prevent, since
	// it breaks a deployment that works.
	if !enforced {
		return LockedMemoryLimit{Bytes: limit, Source: LimitNotEnforced}
	}

	// Zero reaches here as a bounded ceiling of zero bytes, which is exactly
	// what it is: a process allowed to lock nothing. Every positive budget is
	// then refused, and that is the correct answer rather than a degenerate one.
	return LockedMemoryLimit{Bytes: limit, Bounded: true, Source: LimitRLimit}
}

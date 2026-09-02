// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package enclave

// discoverLockedMemoryLimit reports that no locked-memory ceiling exists to
// discover, on the platforms that genuinely have none — Windows, which bounds
// a working-set size rather than a locked-memory rlimit, and the remaining
// GOOS values that define no RLIMIT_MEMLOCK at all.
//
// The platforms that DO expose one are handled and not excused: Linux in
// memlock_linux.go, the five BSDs in memlock_bsd.go. Reporting "unsupported"
// where a ceiling was readable would be a fail-open guard — the budget was
// checkable, the constructor said nothing, and the failure lands later under
// allocation pressure, which is the shape this API exists to remove. This file
// is for the case where there is nothing to read, and its build tag is written
// as an explicit exclusion list so that adding a platform to the BSD file
// cannot leave it silently claimed by both.
//
// It reports NO BOUND rather than an error, and the consequence is this file's
// whole contract: [NewAllocatorWithinRLimit] accepts every positive budget
// here, behaving exactly as [NewAllocator] does. What it promises is that it
// will not REFUSE a budget — not that the budget was checked.
//
// Reporting an error instead was the obvious alternative and is worse. It would
// make the safer constructor unusable on those platforms, and a constructor
// that cannot be called is one callers replace with the unchecked one — at
// which point the check is gone where it does work, in exchange for nothing
// where it never could. The check is an early diagnostic, not a safety
// property: a diagnostic that cannot run is ABSENT, not violated, and nothing
// here weakens what the package still enforces. Locking, guard pages, the
// canary and the wipe are unchanged, and the kernel's own refusal still arrives
// as [ErrLockedMemoryUnavailable] on the allocation that hit it — that path is
// platform-independent and is the authority regardless.
//
// This is the same argument the sibling no-op in dontdump_other.go makes, and
// deliberately so: on a platform missing one control, remove that control and
// keep the rest, rather than refusing to work at all.
//
// [LimitUnsupported] rather than [LimitUnlimited] is the reported source, and
// the distinction is not cosmetic. "Unlimited" is a positive claim about the
// host — the kernel was asked and said there is no ceiling. "Unsupported" says
// this package did not look. A caller sizing a budget from configuration will
// want to log which of those it is, since only one of them means the number it
// chose went unexamined.
func discoverLockedMemoryLimit() (LockedMemoryLimit, error) {
	return LockedMemoryLimit{Source: LimitUnsupported}, nil
}

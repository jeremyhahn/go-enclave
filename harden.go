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
	"sync"
)

// ProcessHardening reports which process-wide protections [HardenProcess]
// applied. A field is true only when the protection was read back in effect.
type ProcessHardening struct {
	// NotDumpable is true when the process is marked non-dumpable (Linux
	// prctl PR_SET_DUMPABLE 0).
	NotDumpable bool

	// CoreDumpsDisabled is true when RLIMIT_CORE was lowered to zero, soft and
	// hard, so that no code in the process can raise it again unprivileged.
	CoreDumpsDisabled bool
}

// disableCoreDumps is the RLIMIT_CORE step, a seam so a test can refuse it
// without changing its own process.
var disableCoreDumps = sysDisableCoreDumps

// coreDumpLimit is what the last HardenProcess did to RLIMIT_CORE, for
// CoreDumpsDisabled; set is false until one has run.
var coreDumpLimit struct {
	mu  sync.Mutex
	set bool
	err error
}

// HardenProcess applies the process-wide protections that are the binary's
// choice, not a library's, and reports which took effect. This package never
// calls it, and importing the package changes no process state; a main
// package opts in, normally first thing in main.
//
// Where the platform has RLIMIT_CORE (every supported GOOS but Windows) it
// lowers the limit to zero, soft and hard, and reads it back; [CoreDumpsDisabled]
// then reports the result. The limit is best effort and does not bind a piped
// Linux core_pattern (core(5)); there the non-dumpable flag below, and the
// verified per-mapping exclusion (MADV_DONTDUMP, MAP_NOCORE, MAP_CONCEAL), are
// what keep enclave pages out of dumps.
//
// On Linux it also marks the process non-dumpable with prctl(PR_SET_DUMPABLE,
// 0) and reads the flag back. That stops core dumps, including ones piped to
// a collector, and stops other processes of the same uid from attaching with
// ptrace or reading /proc/<pid>/mem. The cost is the same list: same-uid
// debuggers, profilers and crash collectors stop working, and /proc/<pid>
// files become owned by root, so same-uid tools lose the restricted ones
// (maps, fd, environ). Children created by fork inherit the flag; an execve
// of an ordinary binary resets it, so exec'd children are dumpable again.
//
// Every step is attempted, and the report holds each that took. A refusal or
// a disagreeing read-back is a *[ProcessHardeningError] for the first step
// that failed; a failed RLIMIT_CORE step is one whose Cause is a
// *[CoreDumpLimitError], so the error also matches [ErrCoreDumpLimitFailed].
// Where neither step exists (Windows) it applies nothing and returns
// [ErrProcessHardeningUnsupported].
func HardenProcess() (ProcessHardening, error) {
	var report ProcessHardening
	var failed error

	dumpable := markNotDumpable()
	switch {
	case dumpable == nil:
		report.NotDumpable = true
	case !errors.Is(dumpable, ErrProcessHardeningUnsupported):
		failed = dumpable
	}

	core := lowerCoreDumpLimit()
	switch {
	case core == nil:
		report.CoreDumpsDisabled = true
	case errors.Is(core, ErrCoreDumpLimitUnsupported):
		if errors.Is(dumpable, ErrProcessHardeningUnsupported) {
			return ProcessHardening{}, ErrProcessHardeningUnsupported
		}
	case failed == nil:
		failed = &ProcessHardeningError{Cause: core}
	}
	return report, failed
}

// lowerCoreDumpLimit runs the RLIMIT_CORE step and records its result for
// CoreDumpsDisabled: nil, ErrCoreDumpLimitUnsupported, or a *CoreDumpLimitError.
func lowerCoreDumpLimit() error {
	err := disableCoreDumps()
	if err != nil && !errors.Is(err, ErrCoreDumpLimitUnsupported) {
		err = &CoreDumpLimitError{Cause: err}
	}
	coreDumpLimit.mu.Lock()
	coreDumpLimit.set, coreDumpLimit.err = true, err
	coreDumpLimit.mu.Unlock()
	return err
}

// CoreDumpsDisabled reports what the last [HardenProcess] did to RLIMIT_CORE:
// nil when it lowered the limit to zero, soft and hard, or a
// *[CoreDumpLimitError] when it could not. Before HardenProcess has run it is
// [ErrCoreDumpLimitNotApplied], and on Windows it is always
// [ErrCoreDumpLimitUnsupported]. Constructors do not consult it.
func CoreDumpsDisabled() error {
	coreDumpLimit.mu.Lock()
	defer coreDumpLimit.mu.Unlock()
	if !coreDumpLimit.set {
		return coreDumpsBeforeHardening
	}
	return coreDumpLimit.err
}

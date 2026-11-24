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

// HardenProcess lowers RLIMIT_CORE to zero and, on Linux, marks the process non-dumpable, reporting which took effect; call it from main.
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

// CoreDumpsDisabled reports what the last [HardenProcess] did to RLIMIT_CORE.
func CoreDumpsDisabled() error {
	coreDumpLimit.mu.Lock()
	defer coreDumpLimit.mu.Unlock()
	if !coreDumpLimit.set {
		return coreDumpsBeforeHardening
	}
	return coreDumpLimit.err
}

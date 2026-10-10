// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"os"

	"golang.org/x/sys/unix"
)

// setDumpable and getDumpable are prctl PR_SET_DUMPABLE and PR_GET_DUMPABLE,
// seams so a test can refuse them without changing its own process.
var (
	setDumpable = func(v uintptr) error {
		return os.NewSyscallError("prctl", unix.Prctl(unix.PR_SET_DUMPABLE, v, 0, 0, 0))
	}
	getDumpable = func() (int, error) {
		v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		return v, os.NewSyscallError("prctl", err)
	}
)

// markNotDumpable is [HardenProcess]'s Linux step: prctl(PR_SET_DUMPABLE, 0),
// then a read-back. A refusal or a disagreeing read-back is a
// *ProcessHardeningError.
func markNotDumpable() error {
	if err := setDumpable(0); err != nil {
		return &ProcessHardeningError{Cause: err}
	}
	v, err := getDumpable()
	if err != nil {
		return &ProcessHardeningError{Cause: err}
	}
	if v != 0 {
		return &ProcessHardeningError{Cause: errDumpableNotCleared}
	}
	return nil
}

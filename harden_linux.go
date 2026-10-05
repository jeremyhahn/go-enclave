// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

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

// HardenProcess applies the process-wide protections that are the BINARY's
// choice, not a library's, and reports which took effect. It is never called by
// this package; a main package opts in, normally first thing in main.
//
// On Linux it marks the process non-dumpable with prctl(PR_SET_DUMPABLE, 0) and
// reads the flag back. That stops core dumps, including ones piped to a
// collector, and stops other processes of the same uid from attaching with
// ptrace or reading /proc/<pid>/mem. The cost is the same list: same-uid
// debuggers, profilers and crash collectors stop working, and /proc/<pid> files
// become owned by root, so same-uid tools lose the restricted ones (maps, fd,
// environ). Children created by fork inherit the flag; an execve of an ordinary
// binary resets it, so exec'd children are dumpable again.
//
// On other platforms it returns [ErrProcessHardeningUnsupported].
func HardenProcess() (ProcessHardening, error) {
	if err := setDumpable(0); err != nil {
		return ProcessHardening{}, &ProcessHardeningError{Cause: err}
	}
	v, err := getDumpable()
	if err != nil {
		return ProcessHardening{}, &ProcessHardeningError{Cause: err}
	}
	if v != 0 {
		return ProcessHardening{}, &ProcessHardeningError{Cause: errDumpableNotCleared}
	}
	return ProcessHardening{NotDumpable: true}, nil
}

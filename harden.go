// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "errors"

// ProcessHardening reports which process-wide protections [HardenProcess]
// applied. A field is true only when the protection was read back in effect.
type ProcessHardening struct {
	// NotDumpable is true when the process is marked non-dumpable (Linux
	// prctl PR_SET_DUMPABLE 0).
	NotDumpable bool
}

// ErrProcessHardeningUnsupported is what [HardenProcess] reports on a platform
// where this package has no process-wide hardening to apply.
var ErrProcessHardeningUnsupported = errors.New("enclave: this platform has no process hardening this package can apply")

// errDumpableNotCleared reports a PR_SET_DUMPABLE that succeeded but did not
// read back as cleared.
var errDumpableNotCleared = errors.New("enclave: the process is still dumpable after PR_SET_DUMPABLE 0")

// ProcessHardeningError reports a hardening step the kernel refused or that did
// not take effect.
type ProcessHardeningError struct {
	// Cause is the refused system call, or the read-back that disagreed.
	Cause error
}

// Error implements error.
func (e *ProcessHardeningError) Error() string {
	return "enclave: process hardening failed: " + e.Cause.Error()
}

// Unwrap returns the cause.
func (e *ProcessHardeningError) Unwrap() error { return e.Cause }

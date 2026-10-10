// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package enclave

import (
	"errors"
	"testing"
)

// TestCoreDumpsDisabled_NotAppliedBeforeHardenProcess pins M1 in process: until
// HardenProcess runs, CoreDumpsDisabled says so rather than reporting a limit
// the package never set. The kernel side is checked in a fresh child on Linux
// (TestHardenProcess_CoreLimitNotLoweredAtImport).
func TestCoreDumpsDisabled_NotAppliedBeforeHardenProcess(t *testing.T) {
	if err := CoreDumpsDisabled(); !errors.Is(err, ErrCoreDumpLimitNotApplied) {
		t.Fatalf("CoreDumpsDisabled() = %v before HardenProcess, want ErrCoreDumpLimitNotApplied", err)
	}
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux

package enclave

import (
	"errors"
	"os"
	"runtime"
	"testing"
)

// TestHardenProcess_OffLinux pins the steps off Linux: no non-dumpable flag
// anywhere, and the RLIMIT_CORE step wherever the limit exists. Windows has
// neither, so it applies nothing. The step runs through its seam, so the test
// process itself is never changed.
func TestHardenProcess_OffLinux(t *testing.T) {
	if runtime.GOOS == "windows" {
		report, err := HardenProcess()
		if !errors.Is(err, ErrProcessHardeningUnsupported) {
			t.Errorf("HardenProcess = %v, want ErrProcessHardeningUnsupported", err)
		}
		if report != (ProcessHardening{}) {
			t.Errorf("report = %+v, want nothing reported in effect", report)
		}
		return
	}

	swapCoreDumpSeam(t, func() error { return nil })
	report, err := HardenProcess()
	if err != nil || report != (ProcessHardening{CoreDumpsDisabled: true}) {
		t.Errorf("HardenProcess = (%+v, %v), want only CoreDumpsDisabled and nil", report, err)
	}
	if err := CoreDumpsDisabled(); err != nil {
		t.Errorf("CoreDumpsDisabled() = %v after HardenProcess, want nil", err)
	}

	refused := os.NewSyscallError("setrlimit", errors.New("refused"))
	swapCoreDumpSeam(t, func() error { return refused })
	report, err = HardenProcess()
	var ce *CoreDumpLimitError
	if report != (ProcessHardening{}) || !errors.As(err, &ce) || !errors.Is(err, refused) ||
		!errors.Is(err, ErrProcessHardeningFailed) {
		t.Errorf("HardenProcess = (%+v, %v), want nothing in effect and a *CoreDumpLimitError wrapping the refusal", report, err)
	}
}

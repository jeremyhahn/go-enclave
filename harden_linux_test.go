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
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	hardenMarker    = "GO_ENCLAVE_HARDEN_CHILD"
	hardenConfirmed = "harden child: the kernel reports the process not dumpable and RLIMIT_CORE 0/0"

	coreImportMarker    = "GO_ENCLAVE_CORE_IMPORT_CHILD"
	coreImportConfirmed = "import child: RLIMIT_CORE is the inherited limit"
)

// TestHardenProcess_NotAppliedAtImport pins that importing the package leaves
// the process dumpable: HardenProcess is the binary's choice.
func TestHardenProcess_NotAppliedAtImport(t *testing.T) {
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_DUMPABLE: %v", err)
	}
	if v == 0 {
		t.Fatal("the test process is not dumpable before anything called HardenProcess")
	}
}

// TestHardenProcess_CoreLimitNotLoweredAtImport pins M1: importing the package
// leaves RLIMIT_CORE as the process found it. A fresh child, which has run
// only the package's initialisation, must see the limits this process passes
// it, and CoreDumpsDisabled must say HardenProcess has not run.
func TestHardenProcess_CoreLimitNotLoweredAtImport(t *testing.T) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
		t.Fatalf("getrlimit(RLIMIT_CORE): %v", err)
	}
	inherited := strconv.FormatUint(rl.Cur, 10) + "/" + strconv.FormatUint(rl.Max, 10)

	if want := os.Getenv(coreImportMarker); want != "" {
		if inherited != want {
			t.Fatalf("RLIMIT_CORE = %s after import, want the inherited %s: importing the package changed it", inherited, want)
		}
		if err := CoreDumpsDisabled(); !errors.Is(err, ErrCoreDumpLimitNotApplied) {
			t.Fatalf("CoreDumpsDisabled() = %v before HardenProcess, want ErrCoreDumpLimitNotApplied", err)
		}
		t.Log(coreImportConfirmed)
		return
	}

	if rl.Cur == 0 && rl.Max == 0 {
		t.Skip("RLIMIT_CORE is already 0/0 here, so an import that lowered it could not be told apart")
	}
	out, err := runTestChild(t, "TestHardenProcess_CoreLimitNotLoweredAtImport", coreImportMarker, inherited)
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, coreImportConfirmed) {
		t.Fatalf("subprocess did not confirm the limit was untouched:\n%s", out)
	}
}

// TestHardenProcess_MarksTheProcessNotDumpable runs HardenProcess in a child,
// since the flag and the limit are process-wide, and reads both back from the
// kernel independently of the package.
func TestHardenProcess_MarksTheProcessNotDumpable(t *testing.T) {
	if os.Getenv(hardenMarker) == "1" {
		report, err := HardenProcess()
		if err != nil {
			t.Fatalf("HardenProcess: %v", err)
		}
		if !report.NotDumpable || !report.CoreDumpsDisabled {
			t.Fatalf("HardenProcess report = %+v, want NotDumpable and CoreDumpsDisabled", report)
		}
		if err := CoreDumpsDisabled(); err != nil {
			t.Fatalf("CoreDumpsDisabled() = %v after HardenProcess, want nil", err)
		}
		var rl unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
			t.Fatalf("getrlimit(RLIMIT_CORE): %v", err)
		}
		if rl.Cur != 0 || rl.Max != 0 {
			t.Fatalf("RLIMIT_CORE = {cur %d, max %d} after HardenProcess, want {0, 0}", rl.Cur, rl.Max)
		}
		v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil {
			t.Fatalf("PR_GET_DUMPABLE: %v", err)
		}
		if v != 0 {
			t.Fatalf("PR_GET_DUMPABLE = %d after HardenProcess, want 0", v)
		}
		t.Log(hardenConfirmed)
		return
	}

	out, err := runTestChild(t, "TestHardenProcess_MarksTheProcessNotDumpable", hardenMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, hardenConfirmed) {
		t.Fatalf("subprocess did not confirm the process was made non-dumpable:\n%s", out)
	}
}

// TestHardenProcess_ReportsFailure refuses each step through the seams, so the
// test process itself is never changed.
func TestHardenProcess_ReportsFailure(t *testing.T) {
	setOK := func(uintptr) error { return nil }
	coreOK := func() error { return nil }
	for _, tc := range []struct {
		name string
		set  func(uintptr) error
		get  func() (int, error)
		want error
	}{
		{"set refused", func(uintptr) error { return os.NewSyscallError("prctl", unix.EPERM) },
			func() (int, error) { return 1, nil }, unix.EPERM},
		{"read-back refused", setOK, func() (int, error) { return 0, os.NewSyscallError("prctl", unix.EINVAL) }, unix.EINVAL},
		{"still dumpable", setOK, func() (int, error) { return 1, nil }, errDumpableNotCleared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swapSeam(t, &setDumpable, tc.set)
			swapSeam(t, &getDumpable, tc.get)
			swapCoreDumpSeam(t, coreOK)
			report, err := HardenProcess()
			if want := (ProcessHardening{CoreDumpsDisabled: true}); report != want {
				t.Errorf("report = %+v, want %+v: the core limit still applies", report, want)
			}
			var he *ProcessHardeningError
			if !errors.As(err, &he) || !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want a *ProcessHardeningError wrapping %v", err, tc.want)
			}
			if errors.Is(err, ErrCoreDumpLimitFailed) {
				t.Errorf("err = %v matches ErrCoreDumpLimitFailed, but only the dumpable step failed", err)
			}
		})
	}

	var gotArg uintptr = 99
	swapSeam(t, &setDumpable, func(v uintptr) error { gotArg = v; return nil })
	swapSeam(t, &getDumpable, func() (int, error) { return 0, nil })
	swapCoreDumpSeam(t, coreOK)
	if _, err := HardenProcess(); err != nil || gotArg != 0 {
		t.Errorf("HardenProcess = %v with PR_SET_DUMPABLE(%d), want nil with PR_SET_DUMPABLE(0)", err, gotArg)
	}
}

// TestHardenProcess_ReportsACoreLimitFailure pins M1's typed error: a refused
// or disagreeing RLIMIT_CORE step is a *ProcessHardeningError whose Cause is a
// *CoreDumpLimitError, the other step still applies, and CoreDumpsDisabled
// reports the same failure. When both steps fail the first is returned and
// CoreDumpsDisabled still carries the second.
func TestHardenProcess_ReportsACoreLimitFailure(t *testing.T) {
	for name, cause := range map[string]error{
		"setrlimit refused": os.NewSyscallError("setrlimit", unix.EPERM),
		"getrlimit refused": os.NewSyscallError("getrlimit", unix.EINVAL),
		"not zero":          errCoreLimitNotCleared,
	} {
		t.Run(name, func(t *testing.T) {
			swapSeam(t, &setDumpable, func(uintptr) error { return nil })
			swapSeam(t, &getDumpable, func() (int, error) { return 0, nil })
			swapCoreDumpSeam(t, func() error { return cause })

			report, err := HardenProcess()
			if want := (ProcessHardening{NotDumpable: true}); report != want {
				t.Errorf("report = %+v, want %+v", report, want)
			}
			var he *ProcessHardeningError
			var ce *CoreDumpLimitError
			if !errors.As(err, &he) || !errors.As(err, &ce) || !errors.Is(err, cause) {
				t.Errorf("err = %v, want a *ProcessHardeningError around a *CoreDumpLimitError wrapping %v", err, cause)
			}
			if !errors.Is(err, ErrProcessHardeningFailed) || !errors.Is(err, ErrCoreDumpLimitFailed) {
				t.Errorf("err = %v, want it to match both ErrProcessHardeningFailed and ErrCoreDumpLimitFailed", err)
			}
			if got := CoreDumpsDisabled(); !errors.As(got, &ce) || !errors.Is(got, cause) {
				t.Errorf("CoreDumpsDisabled() = %v, want the *CoreDumpLimitError wrapping %v", got, cause)
			}
		})
	}

	t.Run("both refused", func(t *testing.T) {
		swapSeam(t, &setDumpable, func(uintptr) error { return os.NewSyscallError("prctl", unix.EPERM) })
		swapCoreDumpSeam(t, func() error { return os.NewSyscallError("setrlimit", unix.EPERM) })

		report, err := HardenProcess()
		if report != (ProcessHardening{}) {
			t.Errorf("report = %+v, want nothing in effect", report)
		}
		if !errors.Is(err, ErrProcessHardeningFailed) || errors.Is(err, ErrCoreDumpLimitFailed) {
			t.Errorf("err = %v, want the first failure, the dumpable step's", err)
		}
		if got := CoreDumpsDisabled(); !errors.Is(got, ErrCoreDumpLimitFailed) {
			t.Errorf("CoreDumpsDisabled() = %v, want ErrCoreDumpLimitFailed", got)
		}
	})
}

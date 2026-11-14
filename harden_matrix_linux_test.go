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
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	coreReadBackMarker    = "GO_ENCLAVE_CORE_READBACK_CHILD"
	coreReadBackConfirmed = "read-back child: RLIMIT_CORE is 0/0 after two calls"
)

// TestHardenProcess_OutcomeMatrix walks every dumpable outcome against every
// core-limit outcome through the seams, so the test process is never changed.
func TestHardenProcess_OutcomeMatrix(t *testing.T) {
	setOK := func(uintptr) error { return nil }
	getZero := func() (int, error) { return 0, nil }
	dumpables := []struct {
		name  string
		set   func(uintptr) error
		get   func() (int, error)
		cause error // nil when the step succeeds
	}{
		{"dumpable ok", setOK, getZero, nil},
		{"set refused", func(uintptr) error { return os.NewSyscallError("prctl", unix.EPERM) }, getZero, unix.EPERM},
		{"read-back error", setOK, func() (int, error) { return 0, os.NewSyscallError("prctl", unix.EINVAL) }, unix.EINVAL},
		{"read-back 1", setOK, func() (int, error) { return 1, nil }, errDumpableNotCleared},
	}
	refused := os.NewSyscallError("setrlimit", unix.EPERM)
	cores := []struct {
		name string
		step func() error
	}{
		{"core ok", func() error { return nil }},
		{"core refused", func() error { return refused }},
		{"core unsupported", func() error { return ErrCoreDumpLimitUnsupported }},
	}

	for _, d := range dumpables {
		for _, c := range cores {
			t.Run(d.name+"/"+c.name, func(t *testing.T) {
				swapSeam(t, &setDumpable, d.set)
				swapSeam(t, &getDumpable, d.get)
				swapCoreDumpSeam(t, c.step)

				report, err := HardenProcess()

				want := ProcessHardening{NotDumpable: d.cause == nil, CoreDumpsDisabled: c.name == "core ok"}
				if report != want {
					t.Errorf("report = %+v, want %+v", report, want)
				}

				var he *ProcessHardeningError
				var ce *CoreDumpLimitError
				switch {
				case d.cause != nil:
					if !errors.As(err, &he) || !errors.Is(err, d.cause) {
						t.Errorf("err = %v, want a *ProcessHardeningError wrapping %v", err, d.cause)
					}
					if errors.Is(err, ErrCoreDumpLimitFailed) {
						t.Errorf("err = %v carries the core failure, want the dumpable cause first", err)
					}
				case c.name == "core refused":
					if !errors.As(err, &he) || !errors.As(he.Cause, &ce) || !errors.Is(err, refused) {
						t.Errorf("err = %v, want a *ProcessHardeningError carrying a *CoreDumpLimitError around %v", err, refused)
					}
				default:
					if err != nil {
						t.Errorf("err = %v, want nil", err)
					}
				}

				got := CoreDumpsDisabled()
				switch c.name {
				case "core ok":
					if got != nil {
						t.Errorf("CoreDumpsDisabled() = %v, want nil", got)
					}
				case "core refused":
					if !errors.As(got, &ce) || !errors.Is(got, refused) {
						t.Errorf("CoreDumpsDisabled() = %v, want a *CoreDumpLimitError around %v", got, refused)
					}
				default:
					if got != ErrCoreDumpLimitUnsupported { //nolint:errorlint // the bare sentinel is the contract
						t.Errorf("CoreDumpsDisabled() = %v, want ErrCoreDumpLimitUnsupported", got)
					}
				}
			})
		}
	}
}

// TestHardenProcess_DumpableUnsupported drives a dumpable step that matches
// ErrProcessHardeningUnsupported against each core-limit outcome.
func TestHardenProcess_DumpableUnsupported(t *testing.T) {
	unsupported := func(uintptr) error { return ErrProcessHardeningUnsupported }
	getZero := func() (int, error) { return 0, nil }

	t.Run("core unsupported", func(t *testing.T) {
		swapSeam(t, &setDumpable, unsupported)
		swapSeam(t, &getDumpable, getZero)
		swapCoreDumpSeam(t, func() error { return ErrCoreDumpLimitUnsupported })

		report, err := HardenProcess()
		if report != (ProcessHardening{}) {
			t.Errorf("report = %+v, want the zero report", report)
		}
		if err != ErrProcessHardeningUnsupported { //nolint:errorlint // the bare sentinel is the contract
			t.Errorf("err = %v, want ErrProcessHardeningUnsupported", err)
		}
		if got := CoreDumpsDisabled(); !errors.Is(got, ErrCoreDumpLimitUnsupported) {
			t.Errorf("CoreDumpsDisabled() = %v, want ErrCoreDumpLimitUnsupported", got)
		}
	})

	t.Run("core refused", func(t *testing.T) {
		refused := os.NewSyscallError("setrlimit", unix.EPERM)
		swapSeam(t, &setDumpable, unsupported)
		swapSeam(t, &getDumpable, getZero)
		swapCoreDumpSeam(t, func() error { return refused })

		report, err := HardenProcess()
		if report != (ProcessHardening{}) {
			t.Errorf("report = %+v, want the zero report", report)
		}
		var he *ProcessHardeningError
		var ce *CoreDumpLimitError
		if !errors.As(err, &he) || !errors.As(he.Cause, &ce) || !errors.Is(err, refused) {
			t.Errorf("err = %v, want the core failure in a *ProcessHardeningError", err)
		}
		if errors.Is(err, ErrProcessHardeningUnsupported) {
			t.Errorf("err = %v matches ErrProcessHardeningUnsupported, want only the core failure", err)
		}
	})

	t.Run("core ok", func(t *testing.T) {
		swapSeam(t, &setDumpable, unsupported)
		swapSeam(t, &getDumpable, getZero)
		swapCoreDumpSeam(t, func() error { return nil })

		report, err := HardenProcess()
		if want := (ProcessHardening{CoreDumpsDisabled: true}); report != want || err != nil {
			t.Errorf("HardenProcess() = %+v, %v; want %+v, nil", report, err, want)
		}
	})
}

// TestSysDisableCoreDumps_ReadBack runs the real call in a child, since it
// lowers the hard limit for good: the child sees 0/0 and a second call
// succeeds. The parent's limit is checked unchanged afterwards.
func TestSysDisableCoreDumps_ReadBack(t *testing.T) {
	if os.Getenv(coreReadBackMarker) != "" {
		for i := range 2 {
			if err := sysDisableCoreDumps(); err != nil {
				t.Fatalf("sysDisableCoreDumps() call %d = %v, want nil", i+1, err)
			}
			var rl unix.Rlimit
			if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
				t.Fatalf("getrlimit(RLIMIT_CORE): %v", err)
			}
			if rl.Cur != 0 || rl.Max != 0 {
				t.Fatalf("RLIMIT_CORE = %d/%d after call %d, want 0/0", rl.Cur, rl.Max, i+1)
			}
		}
		t.Log(coreReadBackConfirmed)
		return
	}

	var before, after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &before); err != nil {
		t.Fatalf("getrlimit(RLIMIT_CORE): %v", err)
	}
	out, err := runTestChild(t, "TestSysDisableCoreDumps_ReadBack", coreReadBackMarker, "1")
	if err != nil {
		t.Fatalf("subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, coreReadBackConfirmed) {
		t.Fatalf("subprocess did not confirm the read-back:\n%s", out)
	}
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &after); err != nil {
		t.Fatalf("getrlimit(RLIMIT_CORE): %v", err)
	}
	if before != after {
		t.Errorf("parent RLIMIT_CORE changed from %d/%d to %d/%d", before.Cur, before.Max, after.Cur, after.Max)
	}
}

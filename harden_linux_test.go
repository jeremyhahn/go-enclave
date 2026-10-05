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
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	hardenMarker    = "GO_ENCLAVE_HARDEN_CHILD"
	hardenConfirmed = "harden child: the kernel reports the process not dumpable"
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

// TestHardenProcess_MarksTheProcessNotDumpable runs HardenProcess in a child,
// since the flag is process-wide, and reads the result back from the kernel
// independently of the package.
func TestHardenProcess_MarksTheProcessNotDumpable(t *testing.T) {
	if os.Getenv(hardenMarker) == "1" {
		report, err := HardenProcess()
		if err != nil {
			t.Fatalf("HardenProcess: %v", err)
		}
		if !report.NotDumpable {
			t.Fatalf("HardenProcess report = %+v, want NotDumpable", report)
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
	prevSet, prevGet := setDumpable, getDumpable
	t.Cleanup(func() { setDumpable, getDumpable = prevSet, prevGet })

	setOK := func(uintptr) error { return nil }
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
			setDumpable, getDumpable = tc.set, tc.get
			report, err := HardenProcess()
			if report.NotDumpable {
				t.Errorf("report = %+v, want nothing reported in effect", report)
			}
			var he *ProcessHardeningError
			if !errors.As(err, &he) || !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want a *ProcessHardeningError wrapping %v", err, tc.want)
			}
		})
	}

	var gotArg uintptr = 99
	setDumpable = func(v uintptr) error { gotArg = v; return nil }
	getDumpable = func() (int, error) { return 0, nil }
	if _, err := HardenProcess(); err != nil || gotArg != 0 {
		t.Errorf("HardenProcess = %v with PR_SET_DUMPABLE(%d), want nil with PR_SET_DUMPABLE(0)", err, gotArg)
	}
}

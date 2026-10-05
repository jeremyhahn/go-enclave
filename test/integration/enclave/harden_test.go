// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration && linux

package enclave_test

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
)

// TestHardenProcess_KernelReportsNotDumpable calls HardenProcess in an
// isolated child and reads the result back from the kernel: PR_GET_DUMPABLE
// is 0 and, for a non-root process, /proc/self/mem is now owned by root.
func TestHardenProcess_KernelReportsNotDumpable(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || v == 0 {
			t.Fatalf("before HardenProcess PR_GET_DUMPABLE = %d, %v; want dumpable: importing must not apply it", v, err)
		}

		report, err := enclave.HardenProcess()
		if err != nil || !report.NotDumpable {
			t.Fatalf("HardenProcess = %+v, %v; want NotDumpable and no error", report, err)
		}
		if v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || v != 0 {
			t.Fatalf("after HardenProcess PR_GET_DUMPABLE = %d, %v; want 0", v, err)
		}
		if os.Getuid() != 0 {
			fi, err := os.Stat("/proc/self/mem")
			if err != nil {
				t.Fatalf("stat /proc/self/mem: %v", err)
			}
			if uid := fi.Sys().(*syscall.Stat_t).Uid; uid != 0 {
				t.Errorf("/proc/self/mem owner = %d after HardenProcess, want root", uid)
			}
		}
	})
}

// TestHardenProcess_ReportsARefusedPrctl refuses PR_SET_DUMPABLE with a
// seccomp filter and requires the refusal back as a typed error with nothing
// reported in effect.
func TestHardenProcess_ReportsARefusedPrctl(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		installErrnoFilter(t, unix.SYS_PRCTL, 0, unix.PR_SET_DUMPABLE, unix.EPERM)

		report, err := enclave.HardenProcess()
		var he *enclave.ProcessHardeningError
		if !errors.As(err, &he) || !errors.Is(err, unix.EPERM) {
			t.Fatalf("HardenProcess = %v, want a *ProcessHardeningError wrapping EPERM", err)
		}
		if !strings.HasPrefix(err.Error(), "enclave: ") {
			t.Errorf("error %q does not name the package", err)
		}
		if report.NotDumpable {
			t.Errorf("report = %+v with the prctl refused, want nothing in effect", report)
		}
		if v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || v == 0 {
			t.Errorf("PR_GET_DUMPABLE = %d, %v; the refused call must have changed nothing", v, err)
		}
	})
}

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

// TestLockedMemory_HardenProcess_KernelReportsNotDumpable calls HardenProcess in an
// isolated child and reads the result back from the kernel: PR_GET_DUMPABLE
// is 0, RLIMIT_CORE is 0 soft and hard and cannot be raised again, and, for a
// non-root process, /proc/self/mem is now owned by root.
func TestLockedMemory_HardenProcess_KernelReportsNotDumpable(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || v == 0 {
			t.Fatalf("before HardenProcess PR_GET_DUMPABLE = %d, %v; want dumpable: importing must not apply it", v, err)
		}
		var before unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &before); err != nil || before.Max == 0 {
			t.Fatalf("before HardenProcess RLIMIT_CORE = %d/%d, %v; want a non-zero hard limit, or lowering it proves nothing",
				before.Cur, before.Max, err)
		}

		report, err := enclave.HardenProcess()
		if err != nil || report != (enclave.ProcessHardening{NotDumpable: true, CoreDumpsDisabled: true}) {
			t.Fatalf("HardenProcess = %+v, %v; want NotDumpable, CoreDumpsDisabled and no error", report, err)
		}
		if v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || v != 0 {
			t.Fatalf("after HardenProcess PR_GET_DUMPABLE = %d, %v; want 0", v, err)
		}
		var rl unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil || rl.Cur != 0 || rl.Max != 0 {
			t.Fatalf("after HardenProcess RLIMIT_CORE = %d/%d, %v; want 0/0", rl.Cur, rl.Max, err)
		}
		if err := enclave.CoreDumpsDisabled(); err != nil {
			t.Errorf("CoreDumpsDisabled() = %v after HardenProcess, want nil", err)
		}
		// Hard limit 0 without CAP_SYS_RESOURCE: cannot be raised.
		if err := unix.Setrlimit(unix.RLIMIT_CORE, &before); !errors.Is(err, unix.EPERM) {
			t.Errorf("raising RLIMIT_CORE back to %d/%d: err = %v, want EPERM", before.Cur, before.Max, err)
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

// TestLockedMemory_HardenProcess_ReportsARefusedPrctl refuses PR_SET_DUMPABLE with a
// seccomp filter and requires the refusal back as a typed error with nothing
// reported in effect.
func TestLockedMemory_HardenProcess_ReportsARefusedPrctl(t *testing.T) {
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

// TestLockedMemory_HardenProcess_ReportsARefusedCoreDumpLimit refuses the
// RLIMIT_CORE change with seccomp, whichever syscall the platform's setrlimit
// is, and requires the refusal back as the typed failure of that step: the
// process is still marked not dumpable and the report says so, and
// CoreDumpsDisabled reports the same failure.
func TestLockedMemory_HardenProcess_ReportsARefusedCoreDumpLimit(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		if err := enclave.CoreDumpsDisabled(); !errors.Is(err, enclave.ErrCoreDumpLimitNotApplied) {
			t.Fatalf("CoreDumpsDisabled() = %v before HardenProcess, want ErrCoreDumpLimitNotApplied", err)
		}
		installErrnoFilter(t, unix.SYS_SETRLIMIT, 0, unix.RLIMIT_CORE, unix.EPERM)
		installErrnoFilter(t, unix.SYS_PRLIMIT64, 1, unix.RLIMIT_CORE, unix.EPERM)

		report, err := enclave.HardenProcess()
		var he *enclave.ProcessHardeningError
		var ce *enclave.CoreDumpLimitError
		if !errors.As(err, &he) || !errors.As(err, &ce) {
			t.Fatalf("HardenProcess = %v, want a *ProcessHardeningError wrapping a *CoreDumpLimitError", err)
		}
		for _, want := range []error{enclave.ErrProcessHardeningFailed, enclave.ErrCoreDumpLimitFailed, unix.EPERM} {
			if !errors.Is(err, want) {
				t.Errorf("HardenProcess = %v, want it to match %v", err, want)
			}
		}
		if !strings.HasPrefix(err.Error(), "enclave: ") || !strings.HasPrefix(ce.Error(), "enclave: ") {
			t.Errorf("errors %q and %q do not name the package", err, ce)
		}
		if report != (enclave.ProcessHardening{NotDumpable: true}) {
			t.Errorf("report = %+v, want only NotDumpable: the dumpable step succeeded and the core limit did not", report)
		}
		if v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err != nil || v != 0 {
			t.Errorf("PR_GET_DUMPABLE = %d, %v; want 0: the first step stands", v, err)
		}

		got := enclave.CoreDumpsDisabled()
		var stored *enclave.CoreDumpLimitError
		if !errors.As(got, &stored) || !errors.Is(got, enclave.ErrCoreDumpLimitFailed) || !errors.Is(got, unix.EPERM) {
			t.Errorf("CoreDumpsDisabled() = %v, want the *CoreDumpLimitError HardenProcess reported", got)
		}
	})
}

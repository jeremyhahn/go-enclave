// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package enclave_test

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-enclave/test/integration/internal/devcontainer"
)

// TestMemoryEnclave_ImportChangesNoProcessState pins, from the kernel's side,
// that linking go-enclave into a process changes no process state until the
// consumer calls it: the process stays dumpable, nothing is locked,
// RLIMIT_MEMLOCK is where the devcontainer set it, and no secretmem area is
// mapped. RLIMIT_CORE has
// its own test (TestMemoryEnclave_CoreDumpLimitUnchangedByImport).
//
// It runs in a fresh child so no earlier test in this binary has called
// go-enclave, and the body calls nothing in go-enclave. The child gets
// childOpts{}, so applyChildLimits (TestMain) sets no RLIMIT_MEMLOCK: the
// child inherits the parent's, which devcontainer.Refuse checked against
// GO_ENCLAVE_IT_MEMLOCK_BYTES.
func TestMemoryEnclave_ImportChangesNoProcessState(t *testing.T) {
	want, err := devcontainer.EnvInt64(devcontainer.EnvMemlockBytes)
	if err != nil {
		t.Fatal(err)
	}
	isolated(t, childOpts{}, func(t *testing.T) {
		dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil {
			t.Fatalf("prctl(PR_GET_DUMPABLE): %v", err)
		}
		if dumpable != 1 {
			t.Errorf("dumpable: prctl(PR_GET_DUMPABLE) = %d after importing go-enclave, want 1: importing must change no process state", dumpable)
		}

		if got := vmLck(t); got != 0 {
			t.Errorf("locked memory: VmLck = %d bytes after importing go-enclave, want 0: importing must change no process state", got)
		}

		var rl unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
			t.Fatalf("getrlimit(RLIMIT_MEMLOCK): %v", err)
		}
		if rl.Cur != uint64(want) || rl.Max != uint64(want) {
			t.Errorf("RLIMIT_MEMLOCK = %d/%d after importing go-enclave, want the devcontainer's %d/%d: importing must change no process state",
				rl.Cur, rl.Max, want, want)
		}

		maps, err := os.ReadFile("/proc/self/maps")
		if err != nil {
			t.Fatalf("reading /proc/self/maps: %v", err)
		}
		for _, line := range strings.Split(string(maps), "\n") {
			if strings.Contains(line, "secretmem") {
				t.Errorf("secretmem mapping: /proc/self/maps has %q after importing go-enclave, want none: importing must change no process state", line)
			}
		}
		t.Logf("dumpable %d, VmLck 0, RLIMIT_MEMLOCK %d/%d, no secretmem mapping", dumpable, rl.Cur, rl.Max)
	})
}

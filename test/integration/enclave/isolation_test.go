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
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// PER-TEST PROCESS ISOLATION.
//
// go-enclave keeps state that is global to the PROCESS by design: the shutdown
// ledger WipeAll sweeps, the one-shot process Sealer and Allocator, and the
// RLIMIT_MEMLOCK every allocation is charged against. A test sharing a process
// with another would see the other's enclaves in its WipeAll count, its locked
// pages in VmLck and its residue in a memory sweep, and could only install a
// process default once per binary.
//
// So every such test re-executes this test binary, running ONLY itself, in a
// fresh process: isolated(t, opts, body) runs body in the child and, in the
// parent, waits for the child and fails with its output if it failed. The
// child's environment selects it by its full test name and can lower its own
// RLIMIT_MEMLOCK before any test code runs (TestMain → applyChildLimits).
//
// The parent does not trust an exit status alone: `-test.run` matching nothing
// exits 0 with "no tests to run", so the child must also print a marker that
// only a body which ran to completion without failing can print. A child that
// matched nothing, skipped, or was renamed out from under its pattern fails the
// parent.
const (
	envChild        = "GO_ENCLAVE_IT_CHILD"
	envChildMemlock = "GO_ENCLAVE_IT_CHILD_MEMLOCK"
	childOKMarker   = "go-enclave-it: child completed: "
)

// childOpts configures the child process.
type childOpts struct {
	// memlock, when positive, is the RLIMIT_MEMLOCK (soft AND hard) the child
	// runs under. Lowering the hard limit is irreversible without
	// CAP_SYS_RESOURCE, which the devcontainer does not grant, so this is a
	// real ceiling the child cannot lift. Zero inherits the devcontainer's.
	memlock int64
	// memlockZero requests a ceiling of exactly zero, which memlock cannot
	// express since zero means "inherit".
	memlockZero bool
}

// isChild reports whether this process is a re-exec'd child.
func isChild() bool { return os.Getenv(envChild) != "" }

// applyChildLimits applies the child's requested limits. It runs in TestMain,
// before m.Run, so no test code — and no enclave — exists yet.
func applyChildLimits() error {
	s := os.Getenv(envChildMemlock)
	if s == "" {
		return nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return fmt.Errorf("%s=%q: %w", envChildMemlock, s, err)
	}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: v, Max: v}); err != nil {
		return fmt.Errorf("setrlimit(RLIMIT_MEMLOCK, %d): %w", v, err)
	}
	return nil
}

// isolated runs body in a fresh child process (see above).
func isolated(t *testing.T, opts childOpts, body func(t *testing.T)) {
	t.Helper()
	if isChild() {
		if got := os.Getenv(envChild); got != t.Name() {
			t.Fatalf("child for %q is running %q: the -test.run pattern selected the wrong test", got, t.Name())
		}
		// Registered FIRST so it runs LAST: the marker is printed only once
		// every other cleanup has run, and only for a body that RETURNED
		// normally and left the test neither failed nor skipped. A body that
		// called t.FailNow, t.SkipNow or runtime.Goexit, or panicked, never
		// reaches returned = true; t.Skipped catches a skip recorded without
		// unwinding. Skipped subtests are refused by the parent, which reads
		// the child's -test.v output.
		returned := false
		t.Cleanup(func() {
			if returned && !t.Failed() && !t.Skipped() {
				fmt.Println(childOKMarker + t.Name())
			}
		})
		body(t)
		returned = true
		return
	}

	args := []string{
		"-test.run=" + exactRunPattern(t.Name()),
		"-test.count=1",
		"-test.v=true",
	}
	// A coverage run (run-integration-tests.sh) writes counters to the
	// directory named by -test.gocoverdir. The child is the same instrumented
	// binary; handing it the same directory is what makes the code it
	// exercises count — without this every isolated test would be invisible to
	// the coverage floor.
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	// Give the child a deadline inside the parent's, so a hung child dies with
	// its own goroutine dump instead of the parent's.
	if deadline, ok := t.Deadline(); ok {
		if remaining := time.Until(deadline) - 30*time.Second; remaining > 0 {
			args = append(args, "-test.timeout="+remaining.String())
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locating the test binary to re-execute: %v", err)
	}
	cmd := exec.Command(exe, args...) //#nosec G204 -- re-executes this test binary with arguments built here
	cmd.Env = append(os.Environ(), envChild+"="+t.Name())
	switch {
	case opts.memlockZero:
		cmd.Env = append(cmd.Env, envChildMemlock+"=0")
	case opts.memlock > 0:
		cmd.Env = append(cmd.Env, envChildMemlock+"="+strconv.FormatInt(opts.memlock, 10))
	}
	out, runErr := cmd.CombinedOutput()
	completed := strings.Contains(string(out), childOKMarker+t.Name()+"\n")
	skipped := strings.Contains(string(out), "--- SKIP")
	if runErr != nil || !completed || skipped {
		t.Fatalf("isolated child process for %s failed (exit: %v, completion marker present: %t, a skip reported: %t). Child output:\n%s",
			t.Name(), runErr, completed, skipped, out)
	}
	t.Logf("isolated child process output:\n%s", out)
}

// exactRunPattern anchors every element of a (possibly nested) test name, so
// -test.run selects that test and nothing that merely shares a prefix.
func exactRunPattern(name string) string {
	parts := strings.Split(name, "/")
	for i, p := range parts {
		parts[i] = "^" + regexp.QuoteMeta(p) + "$"
	}
	return strings.Join(parts, "/")
}

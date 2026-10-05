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

// Per-test process isolation. WipeAll's ledger, the one-shot process Sealer
// and Allocator, and RLIMIT_MEMLOCK are process-global, so a test that touches
// them re-executes this binary running only itself: isolated(t, opts, body)
// runs body in the child and fails the parent with the child's output if it
// failed. The parent also requires a completion marker, because a -test.run
// pattern that matches nothing exits 0.
const (
	envChild        = "GO_ENCLAVE_IT_CHILD"
	envChildMemlock = "GO_ENCLAVE_IT_CHILD_MEMLOCK"
	childOKMarker   = "go-enclave-it: child completed: "
)

// childOpts configures the child process.
type childOpts struct {
	// memlock, when positive, is the child's RLIMIT_MEMLOCK (soft and hard).
	// Without CAP_SYS_RESOURCE the child cannot raise it again. Zero inherits.
	memlock int64
	// memlockZero requests a ceiling of exactly zero.
	memlockZero bool
}

// isChild reports whether this process is a re-exec'd child.
func isChild() bool { return os.Getenv(envChild) != "" }

// applyChildLimits runs in TestMain before m.Run, so no enclave exists yet.
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

// isolated runs body in a fresh child process.
func isolated(t *testing.T, opts childOpts, body func(t *testing.T)) {
	t.Helper()
	if isChild() {
		if got := os.Getenv(envChild); got != t.Name() {
			t.Fatalf("child for %q is running %q: the -test.run pattern selected the wrong test", got, t.Name())
		}
		// Registered first so it runs last: the marker prints only after every
		// other cleanup, and only if body returned normally (not FailNow,
		// SkipNow, Goexit or panic) and the test neither failed nor skipped.
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
	// Pass -test.gocoverdir through so the child's coverage counts.
	if f := flag.Lookup("test.gocoverdir"); f != nil && f.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+f.Value.String())
	}
	// A deadline inside the parent's makes a hung child dump its own goroutines.
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

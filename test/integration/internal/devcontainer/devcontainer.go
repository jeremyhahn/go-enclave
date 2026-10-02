// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

// Package devcontainer is the integration suites' shared guard: every suite's
// TestMain calls Refuse, which exits unless the process is running in
// build/docker/devcontainer with exactly the security posture and limits
// compose.yaml declares (integration-testing §4). A suite that passes only on a
// workstation is measuring the workstation, and one that passes under
// CAP_IPC_LOCK is measuring a ceiling that does not bind. Shared rather than
// copied so that the posture cannot drift between suites.
package devcontainer

import (
	"bufio"
	"crypto/fips140"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Refuse exits the test binary, naming every reason, unless Problems is empty.
// suite names the suite in the message.
func Refuse(suite string) {
	problems := Problems()
	if len(problems) == 0 {
		return
	}
	fmt.Fprintf(os.Stderr, "go-enclave %s integration suite: REFUSING TO RUN — this is not the devcontainer it was written for.\n", suite)
	fmt.Fprintln(os.Stderr, "Run it with `make integration-test` (or `make integration-test-fips`); never on the host (integration-testing §4).")
	for _, p := range problems {
		fmt.Fprintln(os.Stderr, "  - "+p)
	}
	os.Exit(1)
}

// Environment contract with build/docker/devcontainer/compose.yaml. These are
// read, never defaulted: a missing value is a devcontainer that is not the one
// this suite was written for.
const (
	envDevcontainer = "GO_ENCLAVE_IT_DEVCONTAINER"
	EnvMemlockBytes = "GO_ENCLAVE_IT_MEMLOCK_BYTES"
	EnvCoreBytes    = "GO_ENCLAVE_IT_CORE_BYTES"
	EnvFIPSMode     = "GO_ENCLAVE_IT_FIPS_MODE"
)

// capIPCLock is CAP_IPC_LOCK's bit number (linux/capability.h).
const capIPCLock = 14

// Problems verifies, from the kernel, the posture compose.yaml
// declares. Each line it returns is a reason the suite's results would not
// mean what they claim.
func Problems() []string {
	var problems []string
	if os.Getenv(envDevcontainer) != "1" {
		problems = append(problems, envDevcontainer+" is not 1: not running in build/docker/devcontainer")
		// Nothing below is meaningful on a host; stop here with the one reason
		// that matters.
		return problems
	}

	if os.Geteuid() == 0 {
		problems = append(problems, "running as root: the devcontainer runs as an unprivileged user")
	}

	// No capabilities at all — the effective, permitted and bounding sets are
	// all empty under cap_drop: [ALL]. CAP_IPC_LOCK in particular would make the
	// kernel ignore RLIMIT_MEMLOCK and every admission test vacuous.
	for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapAmb"} {
		v, err := statusHex(field)
		switch {
		case err != nil:
			problems = append(problems, err.Error())
		case v != 0:
			problems = append(problems, fmt.Sprintf("%s = %#x, want 0 (compose.yaml drops ALL capabilities)", field, v))
			if v&(1<<capIPCLock) != 0 {
				problems = append(problems, field+" holds CAP_IPC_LOCK: RLIMIT_MEMLOCK would not bind and the admission tests would be vacuous")
			}
		}
	}
	if v, err := statusInt("NoNewPrivs"); err != nil {
		problems = append(problems, err.Error())
	} else if v != 1 {
		problems = append(problems, "NoNewPrivs is not set (compose.yaml: no-new-privileges)")
	}

	// RLIMIT_MEMLOCK must be finite, soft = hard, and exactly the figure
	// compose.yaml declares — a ceiling that varies with the daemon is not a
	// ceiling a test can be written against.
	want, err := envUint64(EnvMemlockBytes)
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		var rl unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
			problems = append(problems, "getrlimit(RLIMIT_MEMLOCK): "+err.Error())
		} else if rl.Cur != want || rl.Max != want {
			problems = append(problems, fmt.Sprintf("RLIMIT_MEMLOCK is %d/%d, want %d/%d (compose.yaml ulimits.memlock)", rl.Cur, rl.Max, want, want))
		}
	}
	if _, err := EnvInt64(EnvCoreBytes); err != nil {
		problems = append(problems, err.Error())
	}

	if p := checkFIPSMode(); p != "" {
		problems = append(problems, p)
	}
	return problems
}

// checkFIPSMode asserts that the Go runtime's FIPS 140-3 state is exactly the
// one the run was configured for, in BOTH directions: a FIPS run that silently
// lost GOFIPS140/GODEBUG would otherwise pass as an ordinary run and report a
// strict-mode result it never produced.
func checkFIPSMode() string {
	switch mode := os.Getenv(EnvFIPSMode); mode {
	case "only":
		if !fips140.Enabled() || !fips140.Enforced() {
			return fmt.Sprintf("%s=only but fips140.Enabled()=%t Enforced()=%t: GOFIPS140=latest and GODEBUG=fips140=only did not reach the test binary",
				EnvFIPSMode, fips140.Enabled(), fips140.Enforced())
		}
	case "off":
		if fips140.Enabled() {
			return EnvFIPSMode + "=off but FIPS 140-3 mode is enabled: the default run must use Go's defaults"
		}
	default:
		return fmt.Sprintf("%s=%q: want \"off\" or \"only\" (set by compose.yaml and the Makefile)", EnvFIPSMode, mode)
	}
	return ""
}

// envUint64 reads a required positive integer from the environment, in the
// unsigned form a getrlimit reading is compared against.
func envUint64(name string) (uint64, error) {
	s := os.Getenv(name)
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("%s=%q: want a positive integer (set by compose.yaml)", name, s)
	}
	return v, nil
}

// EnvInt64 reads a required positive integer from the environment.
func EnvInt64(name string) (int64, error) {
	s := os.Getenv(name)
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%s=%q: want a positive integer (set by compose.yaml)", name, s)
	}
	return v, nil
}

// statusField returns the value text of one /proc/self/status line.
func statusField(name string) (string, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok && k == name {
			return strings.TrimSpace(v), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("/proc/self/status has no %s line", name)
}

// statusHex reads a hexadecimal /proc/self/status field (the Cap* sets).
func statusHex(name string) (uint64, error) {
	v, err := statusField(name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(v, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("/proc/self/status %s=%q: %w", name, v, err)
	}
	return n, nil
}

// statusInt reads a decimal /proc/self/status field.
func statusInt(name string) (int64, error) {
	v, err := statusField(name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("/proc/self/status %s=%q: %w", name, v, err)
	}
	return n, nil
}

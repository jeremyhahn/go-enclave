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
// compose.yaml declares. A suite that passes only on a workstation is measuring
// the workstation, and one that passes under CAP_IPC_LOCK is measuring a
// ceiling that does not bind.
package devcontainer

import (
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
	in := inputs{
		getenv:       os.Getenv,
		euid:         os.Geteuid(),
		fipsEnabled:  fips140.Enabled(),
		fipsEnforced: fips140.Enforced(),
	}
	if in.getenv(envDevcontainer) == "1" {
		status, err := os.ReadFile("/proc/self/status")
		in.status, in.statusErr = string(status), err
		in.memlockErr = unix.Getrlimit(unix.RLIMIT_MEMLOCK, &in.memlock)
	}
	return problemsFrom(in)
}

// inputs is everything the guard reads from the process and the kernel, so
// that problemsFrom is a pure function of it.
type inputs struct {
	getenv       func(string) string
	status       string // the text of /proc/self/status
	statusErr    error  // reading /proc/self/status failed
	euid         int
	memlock      unix.Rlimit // RLIMIT_MEMLOCK soft (Cur) and hard (Max)
	memlockErr   error       // getrlimit(RLIMIT_MEMLOCK) failed
	fipsEnabled  bool        // fips140.Enabled()
	fipsEnforced bool        // fips140.Enforced()
}

// problemsFrom is Problems over the given inputs.
func problemsFrom(in inputs) []string {
	var problems []string
	if in.getenv(envDevcontainer) != "1" {
		problems = append(problems, envDevcontainer+" is not 1: not running in build/docker/devcontainer")
		// Nothing below is meaningful on a host.
		return problems
	}

	if in.euid == 0 {
		problems = append(problems, "running as root: the devcontainer runs as an unprivileged user")
	}

	// cap_drop: [ALL] empties every set. CAP_IPC_LOCK in particular would make
	// the kernel ignore RLIMIT_MEMLOCK and every admission test vacuous.
	for _, field := range []string{"CapEff", "CapPrm", "CapBnd", "CapAmb"} {
		v, err := statusHex(in.status, in.statusErr, field)
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
	if v, err := statusInt(in.status, in.statusErr, "NoNewPrivs"); err != nil {
		problems = append(problems, err.Error())
	} else if v != 1 {
		problems = append(problems, "NoNewPrivs is not set (compose.yaml: no-new-privileges)")
	}

	// RLIMIT_MEMLOCK must be finite, soft = hard, and exactly the figure
	// compose.yaml declares: the admission tests are written against it.
	want, err := envUint64(in.getenv, EnvMemlockBytes)
	if err != nil {
		problems = append(problems, err.Error())
	} else {
		rl := in.memlock
		if in.memlockErr != nil {
			problems = append(problems, "getrlimit(RLIMIT_MEMLOCK): "+in.memlockErr.Error())
		} else if rl.Cur != want || rl.Max != want {
			problems = append(problems, fmt.Sprintf("RLIMIT_MEMLOCK is %d/%d, want %d/%d (compose.yaml ulimits.memlock)", rl.Cur, rl.Max, want, want))
		}
	}
	if _, err := envInt64(in.getenv, EnvCoreBytes); err != nil {
		problems = append(problems, err.Error())
	}

	if p := checkFIPSMode(in.getenv(EnvFIPSMode), in.fipsEnabled, in.fipsEnforced); p != "" {
		problems = append(problems, p)
	}
	return problems
}

// checkFIPSMode checks the runtime's FIPS 140-3 state in both directions: a
// FIPS run that lost GOFIPS140/GODEBUG would otherwise pass as an ordinary run.
// enabled and enforced are fips140.Enabled() and fips140.Enforced().
func checkFIPSMode(mode string, enabled, enforced bool) string {
	switch mode {
	case "only":
		if !enabled || !enforced {
			return fmt.Sprintf("%s=only but fips140.Enabled()=%t Enforced()=%t: GOFIPS140=latest and GODEBUG=fips140=only did not reach the test binary",
				EnvFIPSMode, enabled, enforced)
		}
	case "off":
		if enabled {
			return EnvFIPSMode + "=off but FIPS 140-3 mode is enabled: the default run must use Go's defaults"
		}
	default:
		return fmt.Sprintf("%s=%q: want \"off\" or \"only\" (set by compose.yaml and the Makefile)", EnvFIPSMode, mode)
	}
	return ""
}

func envUint64(getenv func(string) string, name string) (uint64, error) {
	s := getenv(name)
	v, err := strconv.ParseUint(s, 10, 64)
	if err != nil || v == 0 {
		return 0, fmt.Errorf("%s=%q: want a positive integer (set by compose.yaml)", name, s)
	}
	return v, nil
}

// EnvInt64 reads a required positive integer from the environment.
func EnvInt64(name string) (int64, error) {
	return envInt64(os.Getenv, name)
}

func envInt64(getenv func(string) string, name string) (int64, error) {
	s := getenv(name)
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("%s=%q: want a positive integer (set by compose.yaml)", name, s)
	}
	return v, nil
}

// statusField returns the value of the name line of status, the text of
// /proc/self/status; readErr is the error reading it, if any.
func statusField(status string, readErr error, name string) (string, error) {
	if readErr != nil {
		return "", readErr
	}
	for line := range strings.Lines(status) {
		k, v, ok := strings.Cut(line, ":")
		if ok && k == name {
			return strings.TrimSpace(v), nil
		}
	}
	return "", fmt.Errorf("/proc/self/status has no %s line", name)
}

func statusHex(status string, readErr error, name string) (uint64, error) {
	v, err := statusField(status, readErr, name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(v, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("/proc/self/status %s=%q: %w", name, v, err)
	}
	return n, nil
}

func statusInt(status string, readErr error, name string) (int64, error) {
	v, err := statusField(status, readErr, name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("/proc/self/status %s=%q: %w", name, v, err)
	}
	return n, nil
}

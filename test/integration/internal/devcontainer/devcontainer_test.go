// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package devcontainer

import (
	"bytes"
	"crypto/fips140"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// testEnv is a variable no devcontainer or CI job sets, so each case controls
// it fully through t.Setenv.
const testEnv = "GO_ENCLAVE_IT_DEVCONTAINER_TEST_VALUE"

// refuseChildEnv marks the subprocess TestRefuseExits starts: in it, the test
// calls Refuse instead of spawning.
const refuseChildEnv = "GO_ENCLAVE_IT_DEVCONTAINER_REFUSE_CHILD"

// setOrUnset sets testEnv to value, or unsets it when unset is true; the
// original value is restored when the test ends.
func setOrUnset(t *testing.T, value string, unset bool) {
	t.Helper()
	t.Setenv(testEnv, value)
	if unset {
		if err := os.Unsetenv(testEnv); err != nil {
			t.Fatalf("unsetenv: %v", err)
		}
	}
}

type envCase struct {
	name  string
	value string
	unset bool
}

var badEnvCases = []envCase{
	{name: "unset", unset: true},
	{name: "empty", value: ""},
	{name: "zero", value: "0"},
	{name: "negative", value: "-1"},
	{name: "not a number", value: "abc"},
	{name: "over 64 bits", value: "18446744073709551616"},
}

func TestEnvInt64(t *testing.T) {
	cases := append([]envCase{}, badEnvCases...)
	cases = append(cases, envCase{name: "over int64", value: "9223372036854775808"})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setOrUnset(t, tc.value, tc.unset)
			v, err := EnvInt64(testEnv)
			if err == nil {
				t.Fatalf("EnvInt64(%q) = %d, nil; want an error", tc.value, v)
			}
			if v != 0 {
				t.Errorf("EnvInt64(%q) = %d on error, want 0", tc.value, v)
			}
			if !strings.Contains(err.Error(), testEnv+"=") || !strings.Contains(err.Error(), "want a positive integer") {
				t.Errorf("error %q does not name %s and the positive-integer rule", err, testEnv)
			}
		})
	}
	t.Run("4096", func(t *testing.T) {
		setOrUnset(t, "4096", false)
		v, err := EnvInt64(testEnv)
		if err != nil || v != 4096 {
			t.Fatalf("EnvInt64(4096) = %d, %v; want 4096, nil", v, err)
		}
	})
}

func TestEnvUint64(t *testing.T) {
	for _, tc := range badEnvCases {
		t.Run(tc.name, func(t *testing.T) {
			setOrUnset(t, tc.value, tc.unset)
			v, err := envUint64(testEnv)
			if err == nil {
				t.Fatalf("envUint64(%q) = %d, nil; want an error", tc.value, v)
			}
			if v != 0 {
				t.Errorf("envUint64(%q) = %d on error, want 0", tc.value, v)
			}
			if !strings.Contains(err.Error(), testEnv+"=") || !strings.Contains(err.Error(), "want a positive integer") {
				t.Errorf("error %q does not name %s and the positive-integer rule", err, testEnv)
			}
		})
	}
	ok := []struct {
		value string
		want  uint64
	}{
		{value: "4096", want: 4096},
		{value: "9223372036854775808", want: 1 << 63},
	}
	for _, tc := range ok {
		t.Run(tc.value, func(t *testing.T) {
			setOrUnset(t, tc.value, false)
			v, err := envUint64(testEnv)
			if err != nil || v != tc.want {
				t.Fatalf("envUint64(%q) = %d, %v; want %d, nil", tc.value, v, err, tc.want)
			}
		})
	}
}

func TestCheckFIPSMode(t *testing.T) {
	t.Run("off", func(t *testing.T) {
		if fips140.Enabled() {
			t.Skip("FIPS 140-3 mode is enabled in this run")
		}
		t.Setenv(EnvFIPSMode, "off")
		if p := checkFIPSMode(); p != "" {
			t.Fatalf("checkFIPSMode() with %s=off in a non-FIPS run = %q, want \"\"", EnvFIPSMode, p)
		}
	})
	t.Run("only without FIPS", func(t *testing.T) {
		if fips140.Enabled() && fips140.Enforced() {
			t.Skip("FIPS 140-3 mode is enforced in this run")
		}
		t.Setenv(EnvFIPSMode, "only")
		if p := checkFIPSMode(); !strings.Contains(p, EnvFIPSMode+"=only but") {
			t.Fatalf("checkFIPSMode() with %s=only in a non-enforcing run = %q, want the only-mode problem", EnvFIPSMode, p)
		}
	})
	for _, mode := range []string{"", "on"} {
		t.Run("mode "+mode, func(t *testing.T) {
			t.Setenv(EnvFIPSMode, mode)
			p := checkFIPSMode()
			if !strings.Contains(p, EnvFIPSMode+"=") || !strings.Contains(p, `want "off" or "only"`) {
				t.Fatalf("checkFIPSMode() with %s=%q = %q, want the unknown-mode problem", EnvFIPSMode, mode, p)
			}
		})
	}
}

func TestProblemsOutsideDevcontainer(t *testing.T) {
	t.Setenv(envDevcontainer, "")
	got := Problems()
	want := envDevcontainer + " is not 1: not running in build/docker/devcontainer"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("Problems() = %q, want exactly [%q]", got, want)
	}
}

func TestStatusField(t *testing.T) {
	name, err := statusField("Name")
	if err != nil || name == "" {
		t.Fatalf("statusField(Name) = %q, %v; want a process name, nil", name, err)
	}
	const absent = "NoSuchStatusField"
	v, err := statusField(absent)
	if err == nil || !strings.Contains(err.Error(), "has no "+absent+" line") || v != "" {
		t.Fatalf("statusField(%s) = %q, %v; want \"\" and a missing-line error", absent, v, err)
	}
}

func TestStatusParsers(t *testing.T) {
	if _, err := statusHex("CapBnd"); err != nil {
		t.Errorf("statusHex(CapBnd): %v", err)
	}
	if v, err := statusInt("NoNewPrivs"); err != nil || (v != 0 && v != 1) {
		t.Errorf("statusInt(NoNewPrivs) = %d, %v; want 0 or 1, nil", v, err)
	}
	if _, err := statusHex("Name"); err == nil || !strings.Contains(err.Error(), "/proc/self/status Name=") {
		t.Errorf("statusHex(Name) error = %v, want a parse error naming Name", err)
	}
	if _, err := statusInt("Name"); err == nil || !strings.Contains(err.Error(), "/proc/self/status Name=") {
		t.Errorf("statusInt(Name) error = %v, want a parse error naming Name", err)
	}
	if _, err := statusHex("NoSuchStatusField"); err == nil {
		t.Error("statusHex(NoSuchStatusField) = nil error, want the missing-line error")
	}
	if _, err := statusInt("NoSuchStatusField"); err == nil {
		t.Error("statusInt(NoSuchStatusField) = nil error, want the missing-line error")
	}
}

// TestRefuseExits re-runs this test binary with refuseChildEnv set; the child
// calls Refuse outside the devcontainer, which must exit 1 naming the reason.
func TestRefuseExits(t *testing.T) {
	if os.Getenv(refuseChildEnv) == "1" {
		Refuse("guard-test")
		os.Exit(0) // Refuse returned: the parent sees exit 0 and fails.
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestRefuseExits$")
	cmd.Env = append(os.Environ(), refuseChildEnv+"=1", envDevcontainer+"=")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("child run = %v, want exit status 1; stderr:\n%s", err, stderr.String())
	}
	out := stderr.String()
	for _, want := range []string{
		"go-enclave guard-test integration suite: REFUSING TO RUN",
		"  - " + envDevcontainer + " is not 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr lacks %q:\n%s", want, out)
		}
	}
}

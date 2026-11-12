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
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// lookup is a getenv over a fixed map.
func lookup(env map[string]string) func(string) string {
	return func(name string) string { return env[name] }
}

func TestEnvUint64(t *testing.T) {
	const name = "GO_ENCLAVE_IT_TEST_UINT"
	for _, tc := range []struct {
		val     string
		want    uint64
		wantErr string
	}{
		{val: "65536", want: 65536},
		{val: "", wantErr: `GO_ENCLAVE_IT_TEST_UINT="": want a positive integer (set by compose.yaml)`},
		{val: "0", wantErr: `GO_ENCLAVE_IT_TEST_UINT="0": want a positive integer (set by compose.yaml)`},
		{val: "-1", wantErr: `GO_ENCLAVE_IT_TEST_UINT="-1": want a positive integer (set by compose.yaml)`},
		{val: "64k", wantErr: `GO_ENCLAVE_IT_TEST_UINT="64k": want a positive integer (set by compose.yaml)`},
	} {
		t.Run(tc.val, func(t *testing.T) {
			got, err := envUint64(lookup(map[string]string{name: tc.val}), name)
			checkResult(t, got, err, tc.want, tc.wantErr)
		})
	}
}

func TestEnvInt64(t *testing.T) {
	const name = "GO_ENCLAVE_IT_TEST_INT"
	for _, tc := range []struct {
		val     string
		want    int64
		wantErr string
	}{
		{val: "1048576", want: 1048576},
		{val: "", wantErr: `GO_ENCLAVE_IT_TEST_INT="": want a positive integer (set by compose.yaml)`},
		{val: "0", wantErr: `GO_ENCLAVE_IT_TEST_INT="0": want a positive integer (set by compose.yaml)`},
		{val: "-5", wantErr: `GO_ENCLAVE_IT_TEST_INT="-5": want a positive integer (set by compose.yaml)`},
		{val: "1MiB", wantErr: `GO_ENCLAVE_IT_TEST_INT="1MiB": want a positive integer (set by compose.yaml)`},
	} {
		t.Run(tc.val, func(t *testing.T) {
			t.Setenv(name, tc.val)
			got, err := EnvInt64(name)
			checkResult(t, got, err, tc.want, tc.wantErr)
		})
	}
}

func TestCheckFIPSMode(t *testing.T) {
	for _, tc := range []struct {
		name              string
		mode              string
		enabled, enforced bool
		want              string
	}{
		{name: "off clean", mode: "off"},
		{name: "only clean", mode: "only", enabled: true, enforced: true},
		{name: "off but enabled", mode: "off", enabled: true,
			want: "GO_ENCLAVE_IT_FIPS_MODE=off but FIPS 140-3 mode is enabled: the default run must use Go's defaults"},
		{name: "only but disabled", mode: "only",
			want: "GO_ENCLAVE_IT_FIPS_MODE=only but fips140.Enabled()=false Enforced()=false: GOFIPS140=latest and GODEBUG=fips140=only did not reach the test binary"},
		{name: "only but not enforced", mode: "only", enabled: true,
			want: "GO_ENCLAVE_IT_FIPS_MODE=only but fips140.Enabled()=true Enforced()=false: GOFIPS140=latest and GODEBUG=fips140=only did not reach the test binary"},
		{name: "empty", mode: "",
			want: `GO_ENCLAVE_IT_FIPS_MODE="": want "off" or "only" (set by compose.yaml and the Makefile)`},
		{name: "on", mode: "on",
			want: `GO_ENCLAVE_IT_FIPS_MODE="on": want "off" or "only" (set by compose.yaml and the Makefile)`},
		{name: "upper case", mode: "ONLY", enabled: true, enforced: true,
			want: `GO_ENCLAVE_IT_FIPS_MODE="ONLY": want "off" or "only" (set by compose.yaml and the Makefile)`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := checkFIPSMode(tc.mode, tc.enabled, tc.enforced); got != tc.want {
				t.Errorf("checkFIPSMode() = %q, want %q", got, tc.want)
			}
		})
	}
}

const cleanStatus = "Name:\tdevcontainer.test\nUid:\t1000\t1000\t1000\t1000\n" +
	"CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n" +
	"CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"

// clean is the posture compose.yaml declares; each case changes one thing.
func clean() (map[string]string, inputs) {
	env := map[string]string{
		envDevcontainer: "1",
		EnvMemlockBytes: "67108864",
		EnvCoreBytes:    "1048576",
		EnvFIPSMode:     "off",
	}
	return env, inputs{
		status:  cleanStatus,
		euid:    1000,
		memlock: unix.Rlimit{Cur: 67108864, Max: 67108864},
	}
}

// withStatus replaces the value of the field line of cleanStatus.
func withStatus(field, value string) string {
	var b strings.Builder
	for line := range strings.Lines(cleanStatus) {
		if k, _, _ := strings.Cut(line, ":"); k == field {
			line = field + ":\t" + value + "\n"
		}
		b.WriteString(line)
	}
	return b.String()
}

// withoutStatus drops the field line from cleanStatus.
func withoutStatus(field string) string {
	var b strings.Builder
	for line := range strings.Lines(cleanStatus) {
		if k, _, _ := strings.Cut(line, ":"); k != field {
			b.WriteString(line)
		}
	}
	return b.String()
}

func TestProblemsFrom(t *testing.T) {
	const capsAll = "000001ffffffffff"
	for _, tc := range []struct {
		name   string
		change func(env map[string]string, in *inputs)
		want   []string
	}{
		{name: "clean", change: func(map[string]string, *inputs) {}},
		{name: "fips only clean", change: func(env map[string]string, in *inputs) {
			env[EnvFIPSMode] = "only"
			in.fipsEnabled, in.fipsEnforced = true, true
		}},
		{name: "not the devcontainer", change: func(env map[string]string, in *inputs) {
			env[envDevcontainer] = "0"
			in.euid = 0 // nothing else is checked
		}, want: []string{"GO_ENCLAVE_IT_DEVCONTAINER is not 1: not running in build/docker/devcontainer"}},
		{name: "root", change: func(_ map[string]string, in *inputs) { in.euid = 0 },
			want: []string{"running as root: the devcontainer runs as an unprivileged user"}},
		{name: "CapEff without CAP_IPC_LOCK", change: func(_ map[string]string, in *inputs) {
			in.status = withStatus("CapEff", "0000000000000400")
		}, want: []string{"CapEff = 0x400, want 0 (compose.yaml drops ALL capabilities)"}},
		{name: "CapPrm holds CAP_IPC_LOCK", change: func(_ map[string]string, in *inputs) {
			in.status = withStatus("CapPrm", "0000000000004000")
		}, want: []string{
			"CapPrm = 0x4000, want 0 (compose.yaml drops ALL capabilities)",
			"CapPrm holds CAP_IPC_LOCK: RLIMIT_MEMLOCK would not bind and the admission tests would be vacuous",
		}},
		{name: "CapBnd holds every capability", change: func(_ map[string]string, in *inputs) {
			in.status = withStatus("CapBnd", capsAll)
		}, want: []string{
			"CapBnd = 0x1ffffffffff, want 0 (compose.yaml drops ALL capabilities)",
			"CapBnd holds CAP_IPC_LOCK: RLIMIT_MEMLOCK would not bind and the admission tests would be vacuous",
		}},
		{name: "CapAmb non-zero", change: func(_ map[string]string, in *inputs) {
			in.status = withStatus("CapAmb", "0000000000000001")
		}, want: []string{"CapAmb = 0x1, want 0 (compose.yaml drops ALL capabilities)"}},
		{name: "CapEff malformed", change: func(_ map[string]string, in *inputs) {
			in.status = withStatus("CapEff", "zz")
		}, want: []string{`/proc/self/status CapEff="zz": strconv.ParseUint: parsing "zz": invalid syntax`}},
		{name: "CapAmb line missing", change: func(_ map[string]string, in *inputs) {
			in.status = withoutStatus("CapAmb")
		}, want: []string{"/proc/self/status has no CapAmb line"}},
		{name: "NoNewPrivs 0", change: func(_ map[string]string, in *inputs) {
			in.status = withStatus("NoNewPrivs", "0")
		}, want: []string{"NoNewPrivs is not set (compose.yaml: no-new-privileges)"}},
		{name: "NoNewPrivs line missing", change: func(_ map[string]string, in *inputs) {
			in.status = withoutStatus("NoNewPrivs")
		}, want: []string{"/proc/self/status has no NoNewPrivs line"}},
		{name: "NoNewPrivs malformed", change: func(_ map[string]string, in *inputs) {
			in.status = withStatus("NoNewPrivs", "yes")
		}, want: []string{`/proc/self/status NoNewPrivs="yes": strconv.ParseInt: parsing "yes": invalid syntax`}},
		{name: "status unreadable", change: func(_ map[string]string, in *inputs) {
			in.status, in.statusErr = "", errors.New("open /proc/self/status: permission denied")
		}, want: slices.Repeat([]string{"open /proc/self/status: permission denied"}, 5)},
		{name: "memlock soft differs", change: func(_ map[string]string, in *inputs) {
			in.memlock.Cur = 65536
		}, want: []string{"RLIMIT_MEMLOCK is 65536/67108864, want 67108864/67108864 (compose.yaml ulimits.memlock)"}},
		{name: "memlock hard differs", change: func(_ map[string]string, in *inputs) {
			in.memlock.Max = unix.RLIM_INFINITY
		}, want: []string{"RLIMIT_MEMLOCK is 67108864/18446744073709551615, want 67108864/67108864 (compose.yaml ulimits.memlock)"}},
		{name: "getrlimit fails", change: func(_ map[string]string, in *inputs) {
			in.memlockErr = unix.EPERM
		}, want: []string{"getrlimit(RLIMIT_MEMLOCK): operation not permitted"}},
		{name: "memlock env missing", change: func(env map[string]string, in *inputs) {
			delete(env, EnvMemlockBytes)
			in.memlockErr = unix.EPERM // not consulted without a figure to compare
		}, want: []string{`GO_ENCLAVE_IT_MEMLOCK_BYTES="": want a positive integer (set by compose.yaml)`}},
		{name: "memlock env zero", change: func(env map[string]string, _ *inputs) { env[EnvMemlockBytes] = "0" },
			want: []string{`GO_ENCLAVE_IT_MEMLOCK_BYTES="0": want a positive integer (set by compose.yaml)`}},
		{name: "memlock env non-numeric", change: func(env map[string]string, _ *inputs) { env[EnvMemlockBytes] = "64m" },
			want: []string{`GO_ENCLAVE_IT_MEMLOCK_BYTES="64m": want a positive integer (set by compose.yaml)`}},
		{name: "core env missing", change: func(env map[string]string, _ *inputs) { delete(env, EnvCoreBytes) },
			want: []string{`GO_ENCLAVE_IT_CORE_BYTES="": want a positive integer (set by compose.yaml)`}},
		{name: "core env zero", change: func(env map[string]string, _ *inputs) { env[EnvCoreBytes] = "0" },
			want: []string{`GO_ENCLAVE_IT_CORE_BYTES="0": want a positive integer (set by compose.yaml)`}},
		{name: "core env non-numeric", change: func(env map[string]string, _ *inputs) { env[EnvCoreBytes] = "1g" },
			want: []string{`GO_ENCLAVE_IT_CORE_BYTES="1g": want a positive integer (set by compose.yaml)`}},
		{name: "fips mode unset", change: func(env map[string]string, _ *inputs) { delete(env, EnvFIPSMode) },
			want: []string{`GO_ENCLAVE_IT_FIPS_MODE="": want "off" or "only" (set by compose.yaml and the Makefile)`}},
		{name: "fips only but disabled", change: func(env map[string]string, _ *inputs) { env[EnvFIPSMode] = "only" },
			want: []string{"GO_ENCLAVE_IT_FIPS_MODE=only but fips140.Enabled()=false Enforced()=false: GOFIPS140=latest and GODEBUG=fips140=only did not reach the test binary"}},
		{name: "fips off but enabled", change: func(_ map[string]string, in *inputs) { in.fipsEnabled = true },
			want: []string{"GO_ENCLAVE_IT_FIPS_MODE=off but FIPS 140-3 mode is enabled: the default run must use Go's defaults"}},
		{name: "every refusal at once", change: func(env map[string]string, in *inputs) {
			in.euid = 0
			in.status = withStatus("CapEff", "0000000000004000")
			in.memlock.Cur = 1
			env[EnvCoreBytes] = "-1"
			env[EnvFIPSMode] = "on"
		}, want: []string{
			"running as root: the devcontainer runs as an unprivileged user",
			"CapEff = 0x4000, want 0 (compose.yaml drops ALL capabilities)",
			"CapEff holds CAP_IPC_LOCK: RLIMIT_MEMLOCK would not bind and the admission tests would be vacuous",
			"RLIMIT_MEMLOCK is 1/67108864, want 67108864/67108864 (compose.yaml ulimits.memlock)",
			`GO_ENCLAVE_IT_CORE_BYTES="-1": want a positive integer (set by compose.yaml)`,
			`GO_ENCLAVE_IT_FIPS_MODE="on": want "off" or "only" (set by compose.yaml and the Makefile)`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, in := clean()
			tc.change(env, &in)
			in.getenv = lookup(env)
			if got := problemsFrom(in); !slices.Equal(got, tc.want) {
				t.Errorf("problemsFrom() =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
}

func TestProblemsRefusesOutsideTheDevcontainer(t *testing.T) {
	for _, val := range []string{"", "0", "true"} {
		t.Run(val, func(t *testing.T) {
			t.Setenv(envDevcontainer, val)
			want := []string{"GO_ENCLAVE_IT_DEVCONTAINER is not 1: not running in build/docker/devcontainer"}
			if got := Problems(); !slices.Equal(got, want) {
				t.Errorf("Problems() = %q, want %q", got, want)
			}
		})
	}
}

func checkResult[T comparable](t *testing.T, got T, err error, want T, wantErr string) {
	t.Helper()
	if wantErr != "" {
		if err == nil || err.Error() != wantErr {
			t.Fatalf("err = %v, want %q", err, wantErr)
		}
		return
	}
	if err != nil || got != want {
		t.Fatalf("got %v, %v; want %v, nil", got, err, want)
	}
}

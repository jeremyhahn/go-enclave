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
	"slices"
	"testing"
)

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
			t.Setenv(name, tc.val)
			got, err := envUint64(name)
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

func TestCheckFIPSModeRejectsUnknownModes(t *testing.T) {
	for mode, want := range map[string]string{
		"":     `GO_ENCLAVE_IT_FIPS_MODE="": want "off" or "only" (set by compose.yaml and the Makefile)`,
		"on":   `GO_ENCLAVE_IT_FIPS_MODE="on": want "off" or "only" (set by compose.yaml and the Makefile)`,
		"ONLY": `GO_ENCLAVE_IT_FIPS_MODE="ONLY": want "off" or "only" (set by compose.yaml and the Makefile)`,
	} {
		t.Run(mode, func(t *testing.T) {
			t.Setenv(EnvFIPSMode, mode)
			if got := checkFIPSMode(); got != want {
				t.Errorf("checkFIPSMode() = %q, want %q", got, want)
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

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
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// refuseChildEnv marks the subprocess TestRefuseExits starts: in it, the test
// calls Refuse instead of spawning.
const refuseChildEnv = "GO_ENCLAVE_IT_DEVCONTAINER_REFUSE_CHILD"

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

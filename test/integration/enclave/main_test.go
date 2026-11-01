// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration && !optee

// Package enclave_test is go-enclave's integration suite. It drives the public
// API (memory enclaves, Allocator, Sealer/Sealed, WipeAll) against the real
// kernel and verifies outcomes from the kernel's side: admission under a real
// RLIMIT_MEMLOCK with VmLck cross-checked, VmFlags and guard pages from
// /proc/self/smaps, plaintext residue swept through /proc/self/mem, sealing with
// the software provider, and the WipeAll shutdown sweep.
//
// It runs only in the project devcontainer (make integration-test,
// make integration-test-fips); TestMain refuses any other environment or a
// devcontainer whose posture differs from compose.yaml. Tests that touch
// process-global state each run in a fresh process (see isolation_test.go).
package enclave_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/jeremyhahn/go-enclave/test/integration/internal/devcontainer"
)

func TestMain(m *testing.M) {
	// A re-exec'd child (isolation_test.go) applies its own limits before any
	// test code runs, and inherits a posture the parent already verified.
	if isChild() {
		if err := applyChildLimits(); err != nil {
			fmt.Fprintf(os.Stderr, "integration child setup: %v\n", err)
			os.Exit(2)
		}
		os.Exit(m.Run())
	}
	devcontainer.Refuse("enclave")
	os.Exit(m.Run())
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

// Package enclave_test is go-enclave's integration suite (#91).
//
// go-enclave has no CLI and no transport, so the bar is integration-testing §9's
// floor for such a library: exercise the UPPERMOST abstraction — MemoryEnclave,
// Allocator, Sealer/SealedEnclave and WipeAll — through the public API exactly as
// a consumer does, against the real kernel, and verify the outcome from the
// kernel's side rather than from the library's own report of it:
//
//   - locked-memory admission against a REAL RLIMIT_MEMLOCK ceiling, with the
//     allocator's accounting checked against /proc/self/status VmLck;
//   - core-dump exclusion and mlock read back from /proc/self/smaps VmFlags,
//     guard pages from the VMA layout, RLIMIT_CORE from getrlimit;
//   - absence of plaintext residue by sweeping every readable mapping of the
//     process through /proc/self/mem;
//   - sealing end to end with the shipped software provider in both modes,
//     context propagation through the provider seam, and providertest's
//     conformance suite against that provider;
//   - the shutdown sweep with live borrows, deadlines and a concurrent caller.
//
// It runs ONLY in the project devcontainer (build/docker/devcontainer), via
// `make integration-test` and `make integration-test-fips`. TestMain refuses to
// run anywhere else, and refuses to run in a devcontainer whose security
// posture or limits differ from what compose.yaml declares — a suite that
// passes only on a workstation is measuring the workstation, and one that
// passes under CAP_IPC_LOCK is measuring a ceiling that does not bind.
//
// Every test that touches process-global state — the shutdown ledger WipeAll
// sweeps, the one-shot process Sealer and Allocator, RLIMIT_MEMLOCK — runs in a
// FRESH PROCESS of its own (see isolation_test.go), so no test can observe or
// disturb another's enclaves, limits or installed defaults, and ordering and
// -count cannot change any result.
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

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration && !optee

// Package enclave_test is the integration suite, verifying the public API from the kernel's side; it runs only in the devcontainer.
package enclave_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/jeremyhahn/go-enclave/test/internal/devcontainer"
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

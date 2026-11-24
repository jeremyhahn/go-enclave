// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration && optee

package enclave_test

import (
	"fmt"
	"os"
	"testing"
)

// TestMain is the optee harness's guest startup, refusing unless the TEE client endpoint exists.
func TestMain(m *testing.M) {
	endpoint := os.Getenv(opteeEndpointVar)
	if endpoint == "" {
		endpoint = "/dev/tee0"
	}
	if _, err := os.Stat(endpoint); err != nil {
		fmt.Fprintf(os.Stderr, "arm-trustzone guest harness: not in the OP-TEE guest: %v\n", err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

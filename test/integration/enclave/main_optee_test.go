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

// TestMain is the guest startup path of the optee-tagged harness, the binary
// scripts/optee-fixture.sh harness runs in the OP-TEE guest under make
// optee-run. The guest has none of the devcontainer's environment, so this
// build replaces main_test.go's devcontainer guard with its own: it refuses
// unless the TEE client endpoint ($GO_ENCLAVE_OPTEE_ENDPOINT, default
// /dev/tee0) exists, which it does only in the guest. The refusal is the
// typed *fs.PathError from os.Stat (errors.Is fs.ErrNotExist). Every
// non-optee build keeps main_test.go's devcontainer guard unchanged.
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

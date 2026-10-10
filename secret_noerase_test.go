// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !(goexperiment.runtimesecret && linux && !android && (amd64 || arm64))

package enclave

import "testing"

// TestKeyScheduleErasure_FalseWithoutRuntimeSecret pins that a build outside
// the erasing configuration does not claim erasure, and that secretDo still
// runs its function, once and before returning.
func TestKeyScheduleErasure_FalseWithoutRuntimeSecret(t *testing.T) {
	if KeyScheduleErasure() {
		t.Fatal("KeyScheduleErasure() = true in a build without GOEXPERIMENT=runtimesecret on linux/amd64 or arm64")
	}

	calls := 0
	secretDo(func() { calls++ })
	if calls != 1 {
		t.Fatalf("secretDo ran its function %d times, want 1", calls)
	}
}

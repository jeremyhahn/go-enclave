// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.
package enclave

import (
	"errors"
	"testing"
)

func TestProcessHardeningError(t *testing.T) {
	cause := errors.New("refused")
	err := error(&ProcessHardeningError{Cause: cause})
	if got, want := err.Error(), "enclave: process hardening failed: refused"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(%v, cause) = false, want the cause reachable", err)
	}
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.
//go:build !linux

package enclave

import (
	"errors"
	"testing"
)

func TestHardenProcess_UnsupportedOffLinux(t *testing.T) {
	report, err := HardenProcess()
	if !errors.Is(err, ErrProcessHardeningUnsupported) {
		t.Errorf("HardenProcess = %v, want ErrProcessHardeningUnsupported", err)
	}
	if report != (ProcessHardening{}) {
		t.Errorf("report = %+v, want nothing reported in effect", report)
	}
}

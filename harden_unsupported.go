// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux

package enclave

// HardenProcess applies the process-wide protections that are the binary's
// choice, not a library's, and reports which took effect. It is implemented on
// Linux only (harden_linux.go); on every other GOOS it applies nothing and
// returns [ErrProcessHardeningUnsupported].
func HardenProcess() (ProcessHardening, error) {
	return ProcessHardening{}, ErrProcessHardeningUnsupported
}

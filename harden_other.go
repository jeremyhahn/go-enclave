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
// choice, not a library's, and reports which took effect. This package
// implements them on Linux only; here it applies nothing and returns
// [ErrProcessHardeningUnsupported]. See the Linux documentation for what it
// does there.
func HardenProcess() (ProcessHardening, error) {
	return ProcessHardening{}, ErrProcessHardeningUnsupported
}

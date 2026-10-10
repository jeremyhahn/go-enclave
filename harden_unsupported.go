// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux

package enclave

// markNotDumpable is [HardenProcess]'s non-dumpable step, which exists on
// Linux only (harden_linux.go): every other GOOS returns
// [ErrProcessHardeningUnsupported] and the step applies nothing.
func markNotDumpable() error { return ErrProcessHardeningUnsupported }

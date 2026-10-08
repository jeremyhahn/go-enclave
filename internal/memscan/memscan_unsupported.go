// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux

package memscan

import "errors"

// Supported reports that this platform cannot sweep its own address space, so
// a residue check reports itself unmeasured rather than passing.
const Supported = false

// UnsupportedReason says why there is no sweep here.
const UnsupportedReason = "sweeping this process's own address space needs /proc/self/mem, which exists only on Linux"

// Find refuses rather than report an empty, clean-looking sweep.
func Find([]byte, uintptr) ([]string, error) {
	return nil, errors.New("memscan: " + UnsupportedReason)
}

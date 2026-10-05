// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build !linux

package providertest

import "errors"

// sweepSupported reports that this platform cannot sweep its own address
// space, so the residue check reports itself unmeasured rather than passing.
const sweepSupported = false

const sweepUnsupportedReason = "sweeping this process's own address space needs /proc/self/mem, which exists only on Linux"

// residueMappings is unreachable while sweepSupported is false.
func residueMappings([]byte, uintptr) ([]string, error) {
	return nil, errors.New("providertest: " + sweepUnsupportedReason)
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "errors"

// The sys* primitives in the osmem_*.go files each make exactly one system
// call, with no hidden wipe, protection change or advice, so every step a
// mapping takes, and its failure policy, is written in mapping.go.

// protection is a page-protection state; each platform file translates it.
type protection uint8

const (
	// protNoAccess is the guard pages' state for the life of a mapping.
	protNoAccess protection = iota + 1
	// protReadOnly is a frozen data region.
	protReadOnly
	// protReadWrite is a fresh mapping, or a region about to be wiped.
	protReadWrite
)

// errInvalidProtection reports a protection outside the defined values, so the
// zero value is refused rather than guessed.
var errInvalidProtection = errors.New("enclave: invalid page protection")

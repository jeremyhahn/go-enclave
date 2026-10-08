// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

// The sys* primitives in the osmem_*.go files each make exactly one system
// call, with no hidden wipe, protection change or advice, so every step a
// mapping takes, and its failure policy, is written in mapping.go.

// protection is a page-protection state; each platform file translates it with
// a protectionTable.
type protection uint8

const (
	// protNoAccess is the guard pages' state for the life of a mapping.
	protNoAccess protection = iota + 1
	// protReadOnly is a frozen data region.
	protReadOnly
	// protReadWrite is a fresh mapping, or a region about to be wiped.
	protReadWrite
)

// protectionTable is a platform's native constant for each protection. Every
// platform states its three values and translates through the one switch below.
type protectionTable[T any] struct {
	noAccess, readOnly, readWrite T
}

// translate returns the native constant for p, or errInvalidProtection.
func (t protectionTable[T]) translate(p protection) (T, error) {
	switch p {
	case protNoAccess:
		return t.noAccess, nil
	case protReadOnly:
		return t.readOnly, nil
	case protReadWrite:
		return t.readWrite, nil
	default:
		var zero T
		return zero, errInvalidProtection
	}
}

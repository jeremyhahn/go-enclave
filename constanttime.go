// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"crypto/subtle"
	"runtime"
)

// Wipe overwrites b with zeroes. On heap memory it is best effort: the bytes
// may already have been swapped, dumped or copied by the runtime.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Stops the compiler eliminating the loop as a dead store.
	runtime.KeepAlive(b)
}

// copyConstantTime copies min(len(dst), len(src)) bytes without branching on
// their contents.
func copyConstantTime(dst, src []byte) {
	n := len(dst)
	if len(src) < n {
		n = len(src)
	}
	subtle.ConstantTimeCopy(1, dst[:n], src[:n])
}

// equalConstantTime compares two slices without branching on their contents.
func equalConstantTime(x, y []byte) bool {
	return subtle.ConstantTimeCompare(x, y) == 1
}

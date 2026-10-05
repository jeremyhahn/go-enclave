// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

// resetProcessAllocatorForTest clears the process allocator so tests can
// exercise installation and the lazy default.
func resetProcessAllocatorForTest() {
	processAllocatorMu.Lock()
	processAllocatorInstance = nil
	processAllocatorMu.Unlock()
}

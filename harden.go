// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

// ProcessHardening reports which process-wide protections [HardenProcess]
// applied. A field is true only when the protection was read back in effect.
type ProcessHardening struct {
	// NotDumpable is true when the process is marked non-dumpable (Linux
	// prctl PR_SET_DUMPABLE 0).
	NotDumpable bool
}

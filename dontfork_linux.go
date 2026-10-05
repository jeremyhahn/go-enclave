// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"os"

	"golang.org/x/sys/unix"
)

// excludeFromFork keeps b out of any child created by fork(2): with
// MADV_DONTFORK the child has no mapping at that address, so a read there
// faults rather than seeing zeros (MADV_WIPEONFORK). A refusal is a denial and
// is reported.
func excludeFromFork(b []byte) error {
	return os.NewSyscallError("madvise", unix.Madvise(b, unix.MADV_DONTFORK))
}

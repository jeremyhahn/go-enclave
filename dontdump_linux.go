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

// coreDumpMapFlags is empty on Linux: the exclusion is the madvise below.
const coreDumpMapFlags = 0

// excludeFromCoreDump marks b so the kernel omits it from any core dump,
// including one piped to a collector that RLIMIT_CORE does not bind.
// MADV_DONTDUMP exists since Linux 3.4, so a failure is a denial (seccomp, a
// sandbox) and fails the allocation.
func excludeFromCoreDump(b []byte) error {
	return os.NewSyscallError("madvise", unix.Madvise(b, unix.MADV_DONTDUMP))
}

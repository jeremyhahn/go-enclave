// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build dragonfly || freebsd

package enclave

import (
	"os"

	"golang.org/x/sys/unix"
)

// coreDumpMapFlags excludes the pages from the moment they are mapped, before
// the madvise below runs.
const coreDumpMapFlags = unix.MAP_NOCORE

// excludeFromCoreDump marks b so the kernel omits it from any core dump,
// independently of RLIMIT_CORE. MAP_NOCORE could be ignored silently, so this
// madvise is the verified step: a failure fails the allocation.
func excludeFromCoreDump(b []byte) error {
	return os.NewSyscallError("madvise", unix.Madvise(b, unix.MADV_NOCORE))
}

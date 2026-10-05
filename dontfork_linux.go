// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

package enclave

import (
	"os"

	"golang.org/x/sys/unix"
)

// excludeFromFork keeps b out of any child created by fork(2): with
// MADV_DONTFORK the child has no mapping at that address at all.
//
// MADV_DONTFORK rather than MADV_WIPEONFORK. Both keep the material out of the
// child, but they fail differently there: WIPEONFORK leaves the range mapped and
// zero-filled, so code in the child that still holds the enclave reads an
// all-zero buffer it can mistake for a key, while DONTFORK makes that read
// fault. Faulting is the fail-closed outcome. DONTFORK has also been in every
// kernel since 2.6.16, so a refusal is a denial (seccomp, a sandbox) and is
// reported, with no "kernel too old" EINVAL to fall back from.
func excludeFromFork(b []byte) error {
	return os.NewSyscallError("madvise", unix.Madvise(b, unix.MADV_DONTFORK))
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build dragonfly || freebsd || linux || openbsd

package enclave

import (
	"os"

	"golang.org/x/sys/unix"
)

// The platforms that compile this file each state their advice in
// madvise_<platform>.go: coreDumpAdvice, forkAdvice and coreDumpMapFlags. Every
// other platform compiles madvise_unsupported.go and gives none.

// noAdvice is the advice a platform states when it has none to give for a
// hook; madviseRegion then makes no call. It is MADV_NORMAL, the default.
const noAdvice = unix.MADV_NORMAL

// madviseRegion is madvise(2) over b with the given advice, the one syscall
// behind both exclusion hooks. A refusal is a denial (seccomp, a sandbox), not a
// kernel too old to know the advice, and is reported.
func madviseRegion(b []byte, advice int) error {
	if advice == noAdvice {
		return nil
	}
	return os.NewSyscallError("madvise", unix.Madvise(b, advice))
}

// excludeFromCoreDump marks b so the kernel omits it from any core dump,
// independently of RLIMIT_CORE, which does not bind a core_pattern pipe. It is
// the verified step: a failure fails the allocation.
func excludeFromCoreDump(b []byte) error { return madviseRegion(b, coreDumpAdvice) }

// excludeFromFork keeps b out of any child created by fork(2): the child has
// no mapping at that address, so a read there faults rather than seeing zeros
// (MADV_WIPEONFORK). A refusal is reported.
func excludeFromFork(b []byte) error { return madviseRegion(b, forkAdvice) }

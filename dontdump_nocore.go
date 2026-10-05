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

// coreDumpMapFlags asks for the exclusion at mapping time as well, with
// MAP_NOCORE, so the pages are never eligible for a core file even in the
// instant between the mmap and the madvise below.
const coreDumpMapFlags = unix.MAP_NOCORE

// excludeFromCoreDump marks b so the kernel omits it from any core dump,
// independently of RLIMIT_CORE.
//
// MADV_NOCORE is the per-mapping equivalent of Linux's MADV_DONTDUMP on
// FreeBSD, where it has been since FreeBSD 4, and on DragonFly, which inherited
// it from there; golang.org/x/sys defines it for both. The mapping already
// carries MAP_NOCORE, but a flag the kernel silently ignored would leave
// nothing to notice, so this call is the VERIFIED one: as on Linux, a failure
// is surfaced and fails the allocation rather than handing back an enclave
// whose pages could be written to disk in plaintext.
func excludeFromCoreDump(b []byte) error {
	return os.NewSyscallError("madvise", unix.Madvise(b, unix.MADV_NOCORE))
}

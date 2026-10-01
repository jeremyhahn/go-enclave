// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build freebsd

package enclave

import "golang.org/x/sys/unix"

// excludeFromCoreDump marks b so the kernel omits it from any core dump,
// independently of RLIMIT_CORE.
//
// MADV_NOCORE is FreeBSD's per-mapping equivalent of Linux's MADV_DONTDUMP and
// has been there since FreeBSD 4. memcall already maps enclave memory with
// MAP_NOCORE and issues this same madvise inside its Lock — but it DISCARDS the
// result, so on its own nothing would notice the exclusion being refused. This
// call is the verified one: as on Linux, a failure is surfaced and fails the
// allocation rather than handing back an enclave whose pages could be written
// to disk in plaintext.
func excludeFromCoreDump(b []byte) error {
	return unix.Madvise(b, unix.MADV_NOCORE)
}

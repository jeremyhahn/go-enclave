// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-enclave.
//
// go-enclave is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build linux

package enclave

import "golang.org/x/sys/unix"

// excludeFromCoreDump marks b so the kernel omits it from any core dump,
// independently of RLIMIT_CORE.
//
// MADV_DONTDUMP has been in Linux since 3.4, so a failure here means the
// mechanism was actively denied — a seccomp filter or a sandbox intercepting
// madvise — and not that the kernel is too old. That is exactly the case where
// the process-wide RLIMIT_CORE hardening is most likely to have been denied
// too, so the caller is told rather than handed an enclave whose pages could be
// written to disk in plaintext.
func excludeFromCoreDump(b []byte) error {
	return unix.Madvise(b, unix.MADV_DONTDUMP)
}

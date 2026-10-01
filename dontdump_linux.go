// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

package enclave

import "golang.org/x/sys/unix"

// coreDumpMapFlags is empty on Linux: there is no mapping-time flag, and the
// exclusion is the madvise below.
const coreDumpMapFlags = 0

// excludeFromCoreDump marks b so the kernel omits it from any core dump,
// independently of RLIMIT_CORE.
//
// On Linux this is the control that matters most, not a second layer: a
// core_pattern that pipes to a collector (systemd-coredump, apport) is not
// bound by RLIMIT_CORE at all (core(5)), but the kernel's dump writer skips a
// VM_DONTDUMP mapping whatever the dump's destination.
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

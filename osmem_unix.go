// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build aix || darwin || dragonfly || freebsd || illumos || linux || netbsd || openbsd || solaris

package enclave

import (
	"os"

	"golang.org/x/sys/unix"
)

// The build constraint is an explicit list, not the unix meta-tag, so a GOOS
// x/sys cannot serve fails in osmem_unsupported.go rather than inside x/sys.

// sysMap returns n bytes of fresh anonymous, private, read-write memory, zeroed
// by the kernel, with the platform's mapping-time core-dump exclusion. The
// slice must be passed to sysUnmap whole: x/sys unmaps only exact extents.
func sysMap(n int) ([]byte, error) {
	b, err := unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON|coreDumpMapFlags)
	if err != nil {
		return nil, os.NewSyscallError("mmap", err)
	}
	return b, nil
}

// sysLock is mlock(2). It fails at the RLIMIT_MEMLOCK ceiling, and on AIX,
// Solaris and illumos it needs a privilege an ordinary process lacks.
func sysLock(b []byte) error {
	return os.NewSyscallError("mlock", unix.Mlock(b))
}

// sysUnlock is munlock(2).
func sysUnlock(b []byte) error {
	return os.NewSyscallError("munlock", unix.Munlock(b))
}

// sysProtect is mprotect(2), moving b to the given protection.
func sysProtect(b []byte, p protection) error {
	prot, err := unixProtection(p)
	if err != nil {
		return err
	}
	return os.NewSyscallError("mprotect", unix.Mprotect(b, prot))
}

// sysUnmap is munmap(2) over a whole mapping from sysMap; it drops any lock.
// It neither wipes nor changes protection first.
func sysUnmap(b []byte) error {
	return os.NewSyscallError("munmap", unix.Munmap(b))
}

// sysDisableCoreDumps sets RLIMIT_CORE to zero, soft and hard, so other code
// in the process cannot raise it again. It does not bind a core_pattern pipe;
// excludeFromCoreDump covers that case.
func sysDisableCoreDumps() error {
	return os.NewSyscallError("setrlimit", unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}))
}

// unixProtection translates a protection to PROT_* bits.
func unixProtection(p protection) (int, error) {
	switch p {
	case protNoAccess:
		return unix.PROT_NONE, nil
	case protReadOnly:
		return unix.PROT_READ, nil
	case protReadWrite:
		return unix.PROT_READ | unix.PROT_WRITE, nil
	default:
		return 0, errInvalidProtection
	}
}

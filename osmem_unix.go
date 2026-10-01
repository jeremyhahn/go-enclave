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

// The build constraint is an explicit list, not the `unix` meta-tag. `unix`
// also matches GOOS values x/sys has no memory-locking wrappers for, and a new
// one added to it by a future Go release would then fail inside x/sys rather
// than in osmem_unsupported.go, which is where an unsupported GOOS is meant to
// be told so. android and ios need no entry: they satisfy linux and darwin.
// illumos satisfies solaris and is listed anyway, because it is a GOOS of its
// own and a reader checking for it should find it.

// sysMap returns n bytes of fresh anonymous, private, read-write memory.
//
// The kernel zero-fills anonymous pages, so the region arrives zeroed and
// nothing here wipes it a second time. coreDumpMapFlags carries the platform's
// mapping-time core-dump exclusion — MAP_NOCORE on FreeBSD and DragonFly,
// MAP_CONCEAL on OpenBSD, nothing elsewhere; see the dontdump files.
//
// The slice is the one unix.Mmap returns and must be handed back to
// [sysUnmap] whole: x/sys tracks mappings by their exact extent and refuses
// to unmap anything else.
func sysMap(n int) ([]byte, error) {
	b, err := unix.Mmap(-1, 0, n, unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON|coreDumpMapFlags)
	if err != nil {
		return nil, os.NewSyscallError("mmap", err)
	}
	return b, nil
}

// sysLock is mlock(2): it pins b's pages in RAM so they are never written to
// swap. It is the call that fails at the RLIMIT_MEMLOCK ceiling, and on AIX,
// Solaris and illumos it needs a privilege an ordinary process lacks.
func sysLock(b []byte) error {
	return os.NewSyscallError("mlock", unix.Mlock(b))
}

// sysUnlock is munlock(2). Most kernels accept pages that are not locked; the
// release path does not rely on that, because Windows does not (see
// mapping.unlocked).
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

// sysUnmap is munmap(2) over a whole mapping returned by [sysMap]. It drops
// any lock on the pages along with them.
//
// It does NOT wipe and does NOT change protection first. The caller does both,
// as separate steps, when it can; when it cannot — a frozen region whose
// mprotect is denied — handing the pages back unwiped is a decision the caller
// makes and reports, not something this primitive does on its behalf.
func sysUnmap(b []byte) error {
	return os.NewSyscallError("munmap", unix.Munmap(b))
}

// sysDisableCoreDumps sets RLIMIT_CORE to zero, soft AND hard, and an
// unprivileged process cannot raise it again.
//
// What that suppresses is narrower than "no core dump", and the difference is
// the reason the per-mapping exclusion exists. A zero RLIMIT_CORE stops the
// kernel writing a core FILE. It does not stop a dump PIPED to a collector:
// when Linux's core_pattern begins with '|' — systemd-coredump, apport and most
// distribution defaults — the kernel ignores RLIMIT_CORE entirely (core(5):
// "RLIMIT_CORE will be ignored if the system is configured to pipe core dumps
// to a program"), and whether the collector then honors the limit it is told
// about is the collector's decision, not this process's. On such a host the
// thing keeping enclave pages out of the dump is [excludeFromCoreDump] —
// MADV_DONTDUMP is applied by the kernel's own dump writer, whatever the
// destination.
//
// It is the same call, with the same argument, that memcall.DisableCoreDumps
// made on every unix platform — setrlimit(RLIMIT_CORE, {0, 0}) — so the
// process-wide hardening a consumer had before #86 is the hardening it has
// now. Lowering the hard limit is deliberate: a soft-only limit is one any
// code in the process can lift back, which would make the guarantee depend on
// every other library's good behavior.
func sysDisableCoreDumps() error {
	return os.NewSyscallError("setrlimit", unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}))
}

// unixProtection translates a [protection] to PROT_* bits.
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

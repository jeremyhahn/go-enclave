// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build windows

package enclave

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sysMap reserves and commits n bytes of private read-write memory with
// VirtualAlloc.
//
// Committed pages are zero-initialized by the system, so the region arrives
// zeroed and nothing here wipes it a second time.
//
// The address comes back as a uintptr, and turning it into a slice is the one
// conversion in this package that go vet's unsafeptr check cannot see the
// safety of. It IS safe: the pages are not Go heap, so the garbage collector
// neither moves nor frees them, and they stay valid until [sysUnmap] releases
// them. The conversion reads the uintptr's storage as an unsafe.Pointer rather
// than converting the value, which is the spelling vet accepts for memory the
// runtime does not own.
func sysMap(n int) ([]byte, error) {
	addr, err := windows.VirtualAlloc(0, uintptr(n), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		return nil, os.NewSyscallError("VirtualAlloc", err)
	}
	base := *(*unsafe.Pointer)(unsafe.Pointer(&addr)) // #nosec G103 -- audited above: VirtualAlloc memory, not Go heap
	return unsafe.Slice((*byte)(base), n), nil        // #nosec G103 -- n is exactly the length VirtualAlloc committed
}

// sysLock is VirtualLock: it pins b's pages in the process's working set so
// they are not written to the pagefile. The number of pages a process may lock
// is bounded by its minimum working-set size, so this is the call that fails
// when that bound is reached.
func sysLock(b []byte) error {
	return os.NewSyscallError("VirtualLock", windows.VirtualLock(regionAddr(b), uintptr(len(b))))
}

// sysUnlock is VirtualUnlock. Unlike munlock it REFUSES pages that are not
// locked, with ERROR_NOT_LOCKED, which is why the release path unlocks at most
// once per mapping (see mapping.unlocked).
func sysUnlock(b []byte) error {
	return os.NewSyscallError("VirtualUnlock", windows.VirtualUnlock(regionAddr(b), uintptr(len(b))))
}

// sysProtect is VirtualProtect, moving b to the given protection.
func sysProtect(b []byte, p protection) error {
	prot, err := windowsProtection(p)
	if err != nil {
		return err
	}
	var previous uint32
	return os.NewSyscallError("VirtualProtect", windows.VirtualProtect(regionAddr(b), uintptr(len(b)), prot, &previous))
}

// sysUnmap releases a whole allocation made by [sysMap] with VirtualFree and
// MEM_RELEASE, which takes the base address and a size of zero and frees the
// entire reservation; any lock on the pages goes with it. Like the unix
// primitive, it neither wipes nor changes protection first.
func sysUnmap(b []byte) error {
	return os.NewSyscallError("VirtualFree", windows.VirtualFree(regionAddr(b), 0, windows.MEM_RELEASE))
}

// sysDisableCoreDumps reports that Windows has no process-wide core-dump limit
// to lower.
//
// Crash dumps on Windows are not governed by anything the process sets for
// itself. Windows Error Reporting writes them under machine policy (the
// LocalDumps registry key), and any process with enough access to this one can
// write one at any time with MiniDumpWriteDump; neither honors VirtualLock,
// and there is no call by which a process opts itself out of either. The one
// per-region control, WerRegisterExcludedMemoryBlock, covers WER reports only
// and is deliberately not used — dontdump_windows.go says why. memcall
// answered this call with nil, which told a
// caller checking [CoreDumpsDisabled] that a hardening step had succeeded when
// none exists. The honest answer is the sentinel.
func sysDisableCoreDumps() error { return ErrCoreDumpLimitUnsupported }

// windowsProtection translates a [protection] to a PAGE_* constant.
func windowsProtection(p protection) (uint32, error) {
	switch p {
	case protNoAccess:
		return windows.PAGE_NOACCESS, nil
	case protReadOnly:
		return windows.PAGE_READONLY, nil
	case protReadWrite:
		return windows.PAGE_READWRITE, nil
	default:
		return 0, errInvalidProtection
	}
}

// regionAddr is the address of b's first byte, as the uintptr the Virtual*
// calls take. unsafe.SliceData is used rather than &b[0] so that an empty
// slice yields an address the system call can refuse, instead of a panic in
// this package.
func regionAddr(b []byte) uintptr {
	return uintptr(unsafe.Pointer(unsafe.SliceData(b))) // #nosec G103 -- the address a Virtual* call takes; never dereferenced here
}

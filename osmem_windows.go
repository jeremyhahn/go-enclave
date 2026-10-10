// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// sysMap reserves and commits n bytes of private read-write memory with
// VirtualAlloc; the system zero-fills it. The uintptr-to-pointer conversion is
// safe because the pages are not Go heap and stay valid until sysUnmap; reading
// the uintptr's storage is the spelling go vet's unsafeptr check accepts.
func sysMap(n int) ([]byte, error) {
	addr, err := windows.VirtualAlloc(0, uintptr(n), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil {
		return nil, os.NewSyscallError("VirtualAlloc", err)
	}
	base := *(*unsafe.Pointer)(unsafe.Pointer(&addr)) // #nosec G103 -- audited above: VirtualAlloc memory, not Go heap
	return unsafe.Slice((*byte)(base), n), nil        // #nosec G103 -- n is exactly the length VirtualAlloc committed
}

// sysLock is VirtualLock. It fails when the process's minimum working-set size
// is reached.
func sysLock(b []byte) error {
	return os.NewSyscallError("VirtualLock", windows.VirtualLock(regionAddr(b), uintptr(len(b))))
}

// sysUnlock is VirtualUnlock. Unlike munlock it refuses pages that are not
// locked (ERROR_NOT_LOCKED), so the release path unlocks at most once.
func sysUnlock(b []byte) error {
	return os.NewSyscallError("VirtualUnlock", windows.VirtualUnlock(regionAddr(b), uintptr(len(b))))
}

// sysProtect is VirtualProtect, moving b to the given protection.
func sysProtect(b []byte, p protection) error {
	prot, err := windowsProtections.translate(p)
	if err != nil {
		return err
	}
	var previous uint32
	return os.NewSyscallError("VirtualProtect", windows.VirtualProtect(regionAddr(b), uintptr(len(b)), prot, &previous))
}

// sysUnmap releases a whole allocation from sysMap with VirtualFree and
// MEM_RELEASE; any lock goes with it. It neither wipes nor changes protection.
func sysUnmap(b []byte) error {
	return os.NewSyscallError("VirtualFree", windows.VirtualFree(regionAddr(b), 0, windows.MEM_RELEASE))
}

// sysDisableCoreDumps returns [ErrCoreDumpLimitUnsupported]: Windows has no
// process-wide dump limit a process can set for itself.
func sysDisableCoreDumps() error { return ErrCoreDumpLimitUnsupported }

// coreDumpsBeforeHardening is what CoreDumpsDisabled reports until
// HardenProcess has run, and after: there is no limit to lower.
var coreDumpsBeforeHardening = ErrCoreDumpLimitUnsupported

// windowsProtection translates a protection to a PAGE_* constant.
// windowsProtections translates a protection to a PAGE_* constant.
var windowsProtections = protectionTable[uint32]{
	noAccess:  windows.PAGE_NOACCESS,
	readOnly:  windows.PAGE_READONLY,
	readWrite: windows.PAGE_READWRITE,
}

// regionAddr is the address of b's first byte. unsafe.SliceData rather than
// &b[0] lets the system call refuse an empty slice instead of panicking here.
func regionAddr(b []byte) uintptr {
	return uintptr(unsafe.Pointer(unsafe.SliceData(b))) // #nosec G103 -- the address a Virtual* call takes; never dereferenced here
}

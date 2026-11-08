// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"testing"
	"unsafe"
)

// TestSysMap_ReturnsZeroedPageAlignedMemory pins what newMapping relies on to
// skip zeroing: exactly the requested length, page-aligned, read-write, zero.
func TestSysMap_ReturnsZeroedPageAlignedMemory(t *testing.T) {
	n := 3 * int(pageSize)
	b := mapPagesForTest(t, n)

	if len(b) != n || cap(b) != n {
		t.Fatalf("sysMap(%d) = len %d cap %d, want both %d", n, len(b), cap(b), n)
	}
	if addr := uintptr(unsafe.Pointer(&b[0])); addr%uintptr(pageSize) != 0 {
		t.Errorf("sysMap returned %#x, which is not page-aligned", addr)
	}
	if !bytes.Equal(b, make([]byte, n)) {
		t.Error("sysMap returned memory that is not zeroed")
	}
	// Writable on arrival: the store would fault otherwise.
	b[0], b[n-1] = 0xA5, 0x5A
}

// TestSysProtect_RefusesAnUnknownProtection pins that an undefined protection
// is refused with errInvalidProtection and leaves the pages unchanged.
func TestSysProtect_RefusesAnUnknownProtection(t *testing.T) {
	b := mapPagesForTest(t, int(pageSize))

	for _, p := range []protection{0, protReadWrite + 1, 0xFF} {
		if err := sysProtect(b, p); !errors.Is(err, errInvalidProtection) {
			t.Errorf("sysProtect(%d) = %v, want errInvalidProtection", p, err)
		}
	}
	// Still read-write: a refused change must not have changed anything.
	b[0] = 1
	if b[0] != 1 {
		t.Error("the region is no longer writable after refused protection changes")
	}
	for _, p := range []protection{protNoAccess, protReadOnly, protReadWrite} {
		if err := sysProtect(b, p); err != nil {
			t.Errorf("sysProtect(%d) on a whole mapping = %v, want nil", p, err)
		}
	}
}

// TestSysPrimitives_ReportTheirSyscall pins that a platform-layer refusal
// names the refused call and keeps the errno reachable.
func TestSysPrimitives_ReportTheirSyscall(t *testing.T) {
	b := mapPagesForTest(t, 2*int(pageSize))

	// Not the mapping's base: munmap and VirtualFree(MEM_RELEASE) both
	// refuse it.
	err := sysUnmap(b[int(pageSize):])
	var sys *os.SyscallError
	if !errors.As(err, &sys) {
		t.Fatalf("sysUnmap of a partial mapping = %v, want an *os.SyscallError", err)
	}
	want := "munmap"
	if runtime.GOOS == "windows" {
		want = "VirtualFree"
	}
	if sys.Syscall != want {
		t.Errorf("the refusal names %q, want %q", sys.Syscall, want)
	}
	if sys.Err == nil {
		t.Error("the refusal carries no underlying error to match on")
	}

	// No platform maps zero bytes.
	m, err := sysMap(0)
	if m != nil {
		t.Errorf("sysMap(0) returned %d bytes alongside %v", len(m), err)
	}
	want = "mmap"
	if runtime.GOOS == "windows" {
		want = "VirtualAlloc"
	}
	if !errors.As(err, &sys) || sys.Syscall != want {
		t.Errorf("sysMap(0) = %v, want an *os.SyscallError naming %q", err, want)
	}
}

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
	"errors"
	"os"
	"runtime/debug"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// mapPage maps one read-write page with sysMap; the caller unmaps it.
func mapPage(t *testing.T) []byte {
	t.Helper()
	b, err := sysMap(os.Getpagesize())
	if err != nil {
		t.Fatalf("sysMap: %v", err)
	}
	return b
}

// writeFaults reports whether a write to b[0] faults.
func writeFaults(b []byte) (faulted bool) {
	old := debug.SetPanicOnFault(true)
	defer debug.SetPanicOnFault(old)
	defer func() {
		if recover() != nil {
			faulted = true
		}
	}()
	b[0] = 0x5a
	return false
}

func TestMadviseNoAdviceMakesNoCall(t *testing.T) {
	// A nil slice would be refused by a real madvise call; noAdvice makes none.
	if err := madviseRegion(nil, noAdvice); err != nil {
		t.Fatalf("madviseRegion(nil, noAdvice) = %v, want nil", err)
	}
}

func TestMadviseUnalignedIsSyscallError(t *testing.T) {
	b := mapPage(t)
	defer func() { _ = sysUnmap(b) }()

	err := madviseRegion(b[1:], unix.MADV_RANDOM)
	if err == nil {
		t.Fatal("madviseRegion on an unaligned slice = nil, want EINVAL")
	}
	var se *os.SyscallError
	if !errors.As(err, &se) {
		t.Fatalf("error %T is not *os.SyscallError: %v", err, err)
	}
	if se.Syscall != "madvise" {
		t.Errorf("SyscallError.Syscall = %q, want madvise", se.Syscall)
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("error %v is not EINVAL", err)
	}
}

func TestMadviseExclusionHooksOnMappedPage(t *testing.T) {
	b := mapPage(t)
	defer func() { _ = sysUnmap(b) }()

	if err := excludeFromCoreDump(b); err != nil {
		t.Errorf("excludeFromCoreDump: %v", err)
	}
	if err := excludeFromFork(b); err != nil {
		t.Errorf("excludeFromFork: %v", err)
	}
}

func TestOSMemTranslate(t *testing.T) {
	table := protectionTable[string]{noAccess: "none", readOnly: "ro", readWrite: "rw"}
	for _, tc := range []struct {
		p    protection
		want string
	}{
		{protNoAccess, "none"},
		{protReadOnly, "ro"},
		{protReadWrite, "rw"},
	} {
		got, err := table.translate(tc.p)
		if err != nil || got != tc.want {
			t.Errorf("translate(%d) = %q, %v; want %q, nil", tc.p, got, err, tc.want)
		}
	}
	for _, p := range []protection{0, protReadWrite + 1, 255} {
		got, err := table.translate(p)
		if !errors.Is(err, errInvalidProtection) {
			t.Errorf("translate(%d) error = %v, want errInvalidProtection", p, err)
		}
		if got != "" {
			t.Errorf("translate(%d) = %q, want the zero value", p, got)
		}
	}
}

func TestOSMemUnixProtections(t *testing.T) {
	for _, tc := range []struct {
		p    protection
		want int
	}{
		{protNoAccess, unix.PROT_NONE},
		{protReadOnly, unix.PROT_READ},
		{protReadWrite, unix.PROT_READ | unix.PROT_WRITE},
	} {
		got, err := unixProtections.translate(tc.p)
		if err != nil || got != tc.want {
			t.Errorf("unixProtections.translate(%d) = %#x, %v; want %#x, nil", tc.p, got, err, tc.want)
		}
	}
}

func TestOSMemMapProtectUnmapRoundTrip(t *testing.T) {
	b := mapPage(t)
	if len(b) != os.Getpagesize() {
		t.Fatalf("sysMap length = %d, want %d", len(b), os.Getpagesize())
	}
	b[0] = 0x11

	if err := sysProtect(b, protReadOnly); err != nil {
		t.Fatalf("sysProtect(readOnly): %v", err)
	}
	if b[0] != 0x11 {
		t.Errorf("read-only page reads %#x, want 0x11", b[0])
	}
	if !writeFaults(b) {
		t.Error("a write to a read-only page did not fault")
	}

	if err := sysProtect(b, protReadWrite); err != nil {
		t.Fatalf("sysProtect(readWrite): %v", err)
	}
	if writeFaults(b) {
		t.Fatal("a write to a read-write page faulted")
	}
	if b[0] != 0x5a {
		t.Errorf("read-write page reads %#x after the write, want 0x5a", b[0])
	}

	if err := sysUnmap(b); err != nil {
		t.Fatalf("sysUnmap: %v", err)
	}
	err := sysUnmap(b)
	if err == nil {
		t.Fatal("second sysUnmap = nil, want an error")
	}
	var se *os.SyscallError
	if !errors.As(err, &se) || se.Syscall != "munmap" {
		t.Errorf("second sysUnmap error = %v, want a munmap *os.SyscallError", err)
	}
}

func TestOSMemProtectInvalidProtection(t *testing.T) {
	b := mapPage(t)
	defer func() { _ = sysUnmap(b) }()

	if err := sysProtect(b, protection(0)); !errors.Is(err, errInvalidProtection) {
		t.Errorf("sysProtect(0) = %v, want errInvalidProtection", err)
	}
	if err := sysProtect(b, protReadWrite+1); !errors.Is(err, errInvalidProtection) {
		t.Errorf("sysProtect(out of range) = %v, want errInvalidProtection", err)
	}
	// The refused call left the page read-write.
	if writeFaults(b) {
		t.Error("the page faulted after a refused sysProtect")
	}
}

func TestOSMemLockUnlock(t *testing.T) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		t.Fatalf("getrlimit(RLIMIT_MEMLOCK): %v", err)
	}
	cur := uint64(rl.Cur) //nolint:unconvert // Cur is int64 on the BSDs
	if cur != uint64(unix.RLIM_INFINITY) && cur < uint64(2*os.Getpagesize()) {
		t.Fatalf("RLIMIT_MEMLOCK %d is too small to lock two pages; the test host must allow it", cur)
	}

	b := mapPage(t)
	defer func() { _ = sysUnmap(b) }()

	if err := sysLock(b); err != nil {
		t.Fatalf("sysLock: %v", err)
	}
	if err := sysUnlock(b); err != nil {
		t.Fatalf("sysUnlock: %v", err)
	}
}

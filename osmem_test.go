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
	"go/build"
	"os"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unsafe"
)

// knownGOOS is every GOOS go/build accepts, ported or not. The ported ones are
// `go tool dist list`; hurd and zos are known to the toolchain without being
// ports, and are here because they are exactly what a hand-maintained build
// constraint forgets — hurd satisfies the `unix` meta-tag, which is why the
// platform file does not use it.
var knownGOOS = []string{
	"aix", "android", "darwin", "dragonfly", "freebsd", "hurd", "illumos", "ios",
	"js", "linux", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows", "zos",
}

// supportedGOOS is the set #86 commits to: every GOOS where golang.org/x/sys
// provides mmap, mlock, munlock, mprotect and munmap (or their Windows
// equivalents). android, ios and illumos are reached through the linux, darwin
// and solaris constraints Go implies for them.
var supportedGOOS = []string{
	"aix", "android", "darwin", "dragonfly", "freebsd", "illumos", "ios",
	"linux", "netbsd", "openbsd", "solaris", "windows",
}

// matchingFiles reports which of files go/build would compile for goos.
// MatchFile applies both the //go:build line and the _GOOS file-name suffix,
// with the implications Go defines (android satisfies linux, illumos solaris,
// ios darwin), so this is the toolchain's answer rather than a re-derivation of
// it.
func matchingFiles(t *testing.T, goos string, files []string) []string {
	t.Helper()
	ctxt := build.Default
	ctxt.GOOS, ctxt.GOARCH, ctxt.CgoEnabled = goos, "amd64", false
	var matched []string
	for _, f := range files {
		ok, err := ctxt.MatchFile(".", f)
		if err != nil {
			t.Fatalf("MatchFile(%s) for GOOS=%s: %v", f, goos, err)
		}
		if ok {
			matched = append(matched, f)
		}
	}
	return matched
}

// TestPlatformLayer_EveryGOOSHasExactlyOneImplementation pins the partition the
// three osmem files claim: every GOOS compiles exactly one of them, the
// supported set compiles a real one, and everything else — including a GOOS
// that satisfies `unix` without having the calls — compiles the file that
// refuses to build. A constraint edited in one file and not its siblings would
// otherwise produce a duplicate definition on one GOOS and a cascade of
// undefined names on another, and nothing in a Linux-only CI would notice.
//
// The per-mapping core-dump files are held to the same rule over the supported
// set, since each defines excludeFromCoreDump.
func TestPlatformLayer_EveryGOOSHasExactlyOneImplementation(t *testing.T) {
	layer := []string{"osmem_unix.go", "osmem_windows.go", "osmem_unsupported.go"}
	dontdump, err := globGo("dontdump_")
	if err != nil {
		t.Fatalf("listing the dontdump files: %v", err)
	}
	if len(dontdump) < 2 {
		t.Fatalf("found %d dontdump files; the second half of this test would be vacuous", len(dontdump))
	}

	for _, goos := range knownGOOS {
		got := matchingFiles(t, goos, layer)
		want := "osmem_unsupported.go"
		switch {
		case goos == "windows":
			want = "osmem_windows.go"
		case slices.Contains(supportedGOOS, goos):
			want = "osmem_unix.go"
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("GOOS=%s compiles %v, want exactly [%s]", goos, got, want)
		}

		if !slices.Contains(supportedGOOS, goos) {
			continue
		}
		if got := matchingFiles(t, goos, dontdump); len(got) != 1 {
			t.Errorf("GOOS=%s compiles core-dump files %v, want exactly one", goos, got)
		}
	}
}

// globGo lists the non-test .go files in the package directory whose names
// start with prefix.
func globGo(prefix string) ([]string, error) {
	entries, err := os.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") {
			files = append(files, name)
		}
	}
	return files, nil
}

// TestSysMap_ReturnsZeroedPageAlignedMemory pins what newMapping relies on
// when it skips zeroing the region itself: the platform hands back exactly the
// length asked for, page-aligned, readable, writable and all zero.
func TestSysMap_ReturnsZeroedPageAlignedMemory(t *testing.T) {
	n := 3 * int(pageSize)
	b, err := sysMap(n)
	if err != nil {
		t.Fatalf("sysMap: %v", err)
	}
	t.Cleanup(func() {
		if err := sysUnmap(b); err != nil {
			t.Errorf("sysUnmap: %v", err)
		}
	})

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

// TestSysProtect_RefusesAnUnknownProtection pins the default branch of the
// platform translation: the zero protection, or any value past the three
// defined ones, is refused with errInvalidProtection rather than mapped to
// some guess — and the pages are left exactly as they were.
func TestSysProtect_RefusesAnUnknownProtection(t *testing.T) {
	b, err := sysMap(int(pageSize))
	if err != nil {
		t.Fatalf("sysMap: %v", err)
	}
	t.Cleanup(func() {
		if err := sysUnmap(b); err != nil {
			t.Errorf("sysUnmap: %v", err)
		}
	})

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

// TestSysPrimitives_ReportTheirSyscall pins that a refusal from the platform
// layer names the call that was refused and keeps the errno reachable, which is
// what makes a LockedMemoryError diagnosable: "mlock: cannot allocate memory"
// and "munmap: invalid argument" are different operator problems. A region
// that is not a whole mapping is the refusal every platform makes on demand.
func TestSysPrimitives_ReportTheirSyscall(t *testing.T) {
	b, err := sysMap(2 * int(pageSize))
	if err != nil {
		t.Fatalf("sysMap: %v", err)
	}
	t.Cleanup(func() {
		if err := sysUnmap(b); err != nil {
			t.Errorf("sysUnmap: %v", err)
		}
	})

	// Not the mapping's base: munmap and VirtualFree(MEM_RELEASE) both refuse
	// it, so the unmap contract — whole mappings only — is enforced, not
	// assumed.
	err = sysUnmap(b[int(pageSize):])
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

	// And the mapping primitive's own refusal: no platform maps zero bytes.
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

// TestCoreDumpsDisabled_UnsupportedOnlyWhereThereIsNoLimit pins the honest
// answer on each side: Windows has no process-wide core-dump limit and must say
// so, and every other platform has one and must never claim otherwise — a
// sentinel returned everywhere would tell a Linux operator the control does
// not exist when it was merely denied, or succeeded.
func TestCoreDumpsDisabled_UnsupportedOnlyWhereThereIsNoLimit(t *testing.T) {
	unsupported := errors.Is(CoreDumpsDisabled(), ErrCoreDumpLimitUnsupported)
	if want := runtime.GOOS == "windows"; unsupported != want {
		t.Errorf("CoreDumpsDisabled() = %v on %s; reports the limit unsupported = %v, want %v",
			CoreDumpsDisabled(), runtime.GOOS, unsupported, want)
	}
}

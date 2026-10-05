// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package providertest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
)

// scratch returns a scan buffer of the shape residueMappings builds, small
// enough that the boundary-straddling case below actually crosses a chunk.
func scratch(chunk, needleLen int) []byte {
	return make([]byte, chunk+needleLen-1)
}

// TestMappingContainsWipesTheScanBuffer pins the per-mapping wipe. The buffer
// ends a scan holding whatever it last read; carried into the scan of the
// mapping the buffer itself lives in, the sweep would find its own copy of the
// needle and report a leak. Whether that bites depends on the order the kernel
// lists mappings in, so no end-to-end test reliably catches it.
func TestMappingContainsWipesTheScanBuffer(t *testing.T) {
	needle := []byte("needle-that-must-not-ride-along-into-the-next-mapping")
	region := make([]byte, 4096)
	copy(region[1000:], needle)

	buf := scratch(2048, len(needle))

	// Control: the scan found it, so the buffer held it. Otherwise an all-zero
	// buffer afterwards would prove nothing.
	if !mappingContains(bytes.NewReader(region), 0, uintptr(len(region)), needle, buf) {
		t.Fatal("control: the scan did not find a needle that is there, so the wipe assertion below is vacuous")
	}
	if !allZero(buf) {
		t.Errorf("the scan buffer still holds what it read after mappingContains returned; the next mapping "+
			"scanned will find THIS copy and report a residue that does not exist in the code under test. "+
			"First non-zero byte at index %d", bytes.IndexFunc(buf, func(r rune) bool { return r != 0 }))
	}
}

// TestMappingContainsWipesTheScanBufferOnAMiss covers the other return path: a
// mapping with no match still leaves its bytes in the buffer, and they can
// include the needle when the excluded home mapping is the one scanned.
func TestMappingContainsWipesTheScanBufferOnAMiss(t *testing.T) {
	needle := []byte("a needle that is not in this region at all")
	region := bytes.Repeat([]byte{0xAB}, 4096)
	buf := scratch(2048, len(needle))

	if mappingContains(bytes.NewReader(region), 0, uintptr(len(region)), needle, buf) {
		t.Fatal("the scan reported a match in a region that does not contain the needle")
	}
	if !allZero(buf) {
		t.Error("the scan buffer still holds the region it read after a MISS; only the hit path is wiped")
	}
}

// scratchingReader is an io.ReaderAt that uses the WHOLE slice it is handed as
// scratch — filling it with fill — and then reports a short read, which the
// io.ReaderAt contract explicitly permits.
type scratchingReader struct {
	fill     byte
	calls    int
	requests []int // len(p) of every call, so a test can prove the reader ran
}

func (r *scratchingReader) ReadAt(p []byte, _ int64) (int, error) {
	r.calls++
	r.requests = append(r.requests, len(p))
	for i := range p {
		p[i] = r.fill
	}
	return 1, io.EOF
}

// TestMappingContainsWipesWhatTheReaderUsedAsScratch pins the bound of the
// wipe: it must cover the prefix requested from ReadAt, not the count ReadAt
// returned, because a reader may scribble over all of p and report one byte.
func TestMappingContainsWipesWhatTheReaderUsedAsScratch(t *testing.T) {
	needle := []byte("not present")
	buf := scratch(2048, len(needle))
	const regionLen = 1500 // shorter than buf: the request is the region, not the buffer

	r := &scratchingReader{fill: 0x5C}
	if mappingContains(r, 0, regionLen, needle, buf) {
		t.Fatal("reported a match the reader never produced")
	}
	// The reader must have been asked for the whole region, or the zero buffer
	// below proves nothing.
	if r.calls == 0 || r.requests[0] != regionLen {
		t.Fatalf("mappingContains called the reader %d time(s) with requests %v; want a first request of %d bytes", r.calls, r.requests, regionLen)
	}
	if !allZero(buf) {
		t.Errorf("the reader's scratch survived mappingContains; first non-zero byte at index %d of the %d "+
			"requested", bytes.IndexFunc(buf, func(r rune) bool { return r != 0 }), regionLen)
	}
}

// TestMappingContainsSpansChunkBoundaries pins the overlap: a needle
// straddling a read boundary must be found.
func TestMappingContainsSpansChunkBoundaries(t *testing.T) {
	needle := []byte("straddle-me-across-the-boundary")
	const chunk = 512
	buf := scratch(chunk, len(needle))
	// A read fills the whole buffer, so the boundary a needle has to straddle
	// is at a multiple of len(buf), not of chunk. Placements inside one read
	// would pass with the overlap deleted.
	read := len(buf)
	region := make([]byte, 4*read)

	for _, start := range []int{read - 5, 2*read - 1, 3*read - len(needle) + 1} {
		t.Run(fmt.Sprintf("start=%d", start), func(t *testing.T) {
			clear(region)
			copy(region[start:], needle)
			if start/read == (start+len(needle)-1)/read {
				t.Fatalf("placement at %d does not cross a %d-byte read boundary; the test would pass "+
					"with the overlap deleted", start, read)
			}
			if !mappingContains(bytes.NewReader(region), 0, uintptr(len(region)), needle, buf) {
				t.Errorf("a needle at offset %d, straddling the %d-byte read boundary at %d, was missed",
					start, read, (start/read+1)*read)
			}
		})
	}
}

// TestParseMapsHeader pins the line recognizer the home exclusion depends on.
// The expected bounds are uint64 so the table compiles on 32-bit targets, where
// a 64-bit address must be rejected rather than narrowed; a row's expected ok
// is its wantOK and "the bound fits this platform's uintptr". The 32-bit row
// keeps every platform asserting at least one successful parse.
func TestParseMapsHeader(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		lo, hi uint64
		wantOK bool
	}{
		{
			name:   "an anonymous mapping",
			line:   "7f0c00000000-7f0c00021000 rw-p 00000000 00:00 0",
			lo:     0x7f0c00000000,
			hi:     0x7f0c00021000,
			wantOK: true,
		},
		{
			name:   "a kernel-labeled anonymous mapping",
			line:   "c000000000-c004000000 rw-p 00000000 00:00 0 \t\t\t\t [anon: Go: heap]",
			lo:     0xc000000000,
			hi:     0xc004000000,
			wantOK: true,
		},
		{
			name:   "a mapping inside 32 bits",
			line:   "08048000-08049000 r-xp 00000000 08:01 1234 /bin/true",
			lo:     0x08048000,
			hi:     0x08049000,
			wantOK: true,
		},
		{name: "empty", line: "", wantOK: false},
		{name: "no range separator", line: "7f0c00000000 rw-p", wantOK: false},
		{name: "not hexadecimal", line: "zzzz-7f0c00021000 rw-p", wantOK: false},
		{name: "high bound not hexadecimal", line: "7f0c00000000-zzzz rw-p", wantOK: false},
		{name: "no fields", line: "7f0c00000000-7f0c00021000", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantOK := tc.wantOK && tc.hi <= uint64(^uintptr(0))
			lo, hi, ok := parseMapsHeader(tc.line)
			if ok != wantOK {
				t.Fatalf("parseMapsHeader ok = %v, want %v", ok, wantOK)
			}
			if ok && (uint64(lo) != tc.lo || uint64(hi) != tc.hi) {
				t.Errorf("parseMapsHeader = %#x-%#x, want %#x-%#x", lo, hi, tc.lo, tc.hi)
			}
		})
	}
}

// TestResidueMappingsFindsAndExcludesHome is the end-to-end check on the real
// address space: a needle held in a live heap slice is findable, and passing
// its own mapping as home excludes it.
func TestResidueMappingsFindsAndExcludesHome(t *testing.T) {
	needle := bytes.Repeat([]byte{0x00}, 48)
	for i := range needle {
		needle[i] = byte(i*7 + 13)
	}

	// Both preconditions fail rather than skip: reading one's own /proc/self
	// needs no privilege on Linux, and a sweep that cannot find a live needle
	// would make the exclusion assertion vacuous.
	hits, err := residueMappings(needle, 0)
	if err != nil {
		t.Fatalf("cannot sweep process memory: %v (the runner must mount /proc and allow a process to read "+
			"its own /proc/self/maps and /proc/self/mem)", err)
	}
	if len(hits) == 0 {
		t.Fatal("the sweep found no mapping holding a needle that is live in this process; it cannot see " +
			"anything here and the exclusion assertion would be vacuous")
	}

	home, err := addrOf(needle)
	if err != nil {
		t.Fatalf("addrOf: %v", err)
	}
	excluded, err := residueMappings(needle, home)
	if err != nil {
		t.Fatalf("residueMappings: %v", err)
	}
	if len(excluded) >= len(hits) {
		t.Errorf("passing the needle's own address as home excluded nothing: %d hits with home=0, %d with "+
			"home=%#x. Every legitimate copy would read as a leak", len(hits), len(excluded), home)
	}
	// Keep the needle alive past both sweeps so neither result can be explained
	// by the collector having reclaimed it.
	if needle[0] == 0xFF && needle[47] == 0xFF {
		t.Fatal("unreachable; this exists only to keep the needle live")
	}
}

// TestSuiteCatchesAProviderThatRetainsACopy is the deliberate-leak control
// for retention by copy. It lives in the Linux file because the residue sweep
// exists only on Linux; TestResidueSweepReportsItselfNotRunOffLinux
// (residue_other_test.go) pins the behavior elsewhere.
func TestSuiteCatchesAProviderThatRetainsACopy(t *testing.T) {
	kept := &retainingProtector{inner: software()}
	wantFail(t, perOp(func() (any, error) { return kept, nil }),
		"no copy of the key is findable in the process after Unprotect returns")
	// Hold the retained copies past the sweep so the failure cannot be
	// explained away as garbage the collector had not yet reached.
	if len(kept.kept) == 0 {
		t.Fatal("the planted provider retained nothing; the control proved nothing")
	}
}

// TestEqualBytes pins that a recovery of the wrong length is not the key,
// whatever its prefix holds.
func TestEqualBytes(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b []byte
		want bool
	}{
		{"equal", []byte("key-bytes"), []byte("key-bytes"), true},
		{"both empty", nil, []byte{}, true},
		{"one byte differs", []byte("key-bytes"), []byte("key-bytez"), false},
		{"a strict prefix", []byte("key-bytes"), []byte("key-byte"), false},
		{"longer", []byte("key-bytes"), []byte("key-bytes!"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := equalBytes(tc.a, tc.b); got != tc.want {
				t.Errorf("equalBytes = %v, want %v", got, tc.want)
			}
		})
	}
}

// mappedRetainer conforms in every visible way and copies every key it
// recovers into a mapping it owns, outside anonymous memory.
type mappedRetainer struct {
	inner  *enclave.SoftwareProvider
	mu     sync.Mutex
	region []byte // written through, when fd < 0
	fd     int    // written through with pwrite, when >= 0
	stored int
}

func (p *mappedRetainer) Protect(ctx context.Context, key []byte) ([]byte, error) {
	return p.inner.Protect(ctx, key)
}

func (p *mappedRetainer) Unprotect(ctx context.Context, blob, key []byte) error {
	if err := p.inner.Unprotect(ctx, blob, key); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fd >= 0 {
		if _, err := unix.Pwrite(p.fd, key, 0); err != nil {
			return err
		}
	} else {
		copy(p.region, key)
	}
	p.stored++
	return nil
}

// TestSuiteCatchesAKeyRetainedInAFileOrDeviceMapping plants the key in every
// kind of mapping /proc/self/maps names with a path, and requires the sweep to
// find it there.
func TestSuiteCatchesAKeyRetainedInAFileOrDeviceMapping(t *testing.T) {
	const property = "no copy of the key is findable in the process after Unprotect returns"
	page := os.Getpagesize()

	mapFd := func(t *testing.T, fd, prot, flags int) []byte {
		t.Helper()
		b, err := unix.Mmap(fd, 0, page, prot, flags)
		if err != nil {
			t.Fatalf("mmap: %v", err)
		}
		t.Cleanup(func() { _ = unix.Munmap(b) })
		return b
	}
	openFile := func(t *testing.T, path string, flag int) int {
		t.Helper()
		fd, err := unix.Open(path, flag|unix.O_CLOEXEC, 0o600)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		return fd
	}
	sizedFile := func(t *testing.T, fd int) {
		t.Helper()
		if err := unix.Ftruncate(fd, int64(page)); err != nil {
			t.Fatalf("ftruncate: %v", err)
		}
	}
	memfd := func(t *testing.T) int {
		t.Helper()
		fd, err := unix.MemfdCreate("providertest-retainer", unix.MFD_CLOEXEC)
		if err != nil {
			t.Fatalf("memfd_create: %v", err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		sizedFile(t, fd)
		return fd
	}
	tempFile := func(t *testing.T) int {
		t.Helper()
		fd := openFile(t, filepath.Join(t.TempDir(), "retained"), unix.O_RDWR|unix.O_CREAT)
		sizedFile(t, fd)
		return fd
	}
	rw := unix.PROT_READ | unix.PROT_WRITE

	tests := []struct {
		name  string
		setup func(t *testing.T) *mappedRetainer
	}{
		{"private /dev/zero mapping", func(t *testing.T) *mappedRetainer {
			return &mappedRetainer{fd: -1, region: mapFd(t, openFile(t, "/dev/zero", unix.O_RDWR), rw, unix.MAP_PRIVATE)}
		}},
		{"shared /dev/zero mapping", func(t *testing.T) *mappedRetainer {
			return &mappedRetainer{fd: -1, region: mapFd(t, openFile(t, "/dev/zero", unix.O_RDWR), rw, unix.MAP_SHARED)}
		}},
		{"writable memfd mapping", func(t *testing.T) *mappedRetainer {
			return &mappedRetainer{fd: -1, region: mapFd(t, memfd(t), rw, unix.MAP_SHARED)}
		}},
		{"read-only memfd mapping written through its descriptor", func(t *testing.T) *mappedRetainer {
			fd := memfd(t)
			mapFd(t, fd, unix.PROT_READ, unix.MAP_SHARED)
			return &mappedRetainer{fd: fd}
		}},
		{"private writable file mapping", func(t *testing.T) *mappedRetainer {
			return &mappedRetainer{fd: -1, region: mapFd(t, tempFile(t), rw, unix.MAP_PRIVATE)}
		}},
		{"shared writable file mapping", func(t *testing.T) *mappedRetainer {
			return &mappedRetainer{fd: -1, region: mapFd(t, tempFile(t), rw, unix.MAP_SHARED)}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.setup(t)
			p.inner = software()
			wantFail(t, perOp(func() (any, error) { return p, nil }), property+": ", "RETAINED a copy")
			if p.stored == 0 {
				t.Fatal("the planted provider stored nothing; the control proved nothing")
			}
		})
	}
}

// TestSweptMapping pins which /proc/self/maps entries the sweep reads. Every
// exclusion is a place a provider could hide a key, so the table names each.
func TestSweptMapping(t *testing.T) {
	for _, tc := range []struct {
		perms, path string
		want        bool
	}{
		{"rw-p", "", true},
		{"r--p", "", true},
		{"rw-p", "[anon: Go: heap]", true},
		{"rw-p", "[stack]", true},
		{"rw-s", "/dev/zero (deleted)", true},
		{"rw-p", "/dev/zero", true},
		{"rw-s", "/memfd:secret (deleted)", true},
		{"r--s", "/memfd:secret (deleted)", true},
		{"r--s", "/dev/shm/secret", true},
		{"r--p", "/SYSV00000000 (deleted)", true},
		{"r--p", "/tmp/unlinked (deleted)", true},
		{"rw-p", "/usr/lib/libc.so.6", true},
		{"rw-s", "/var/tmp/shared", true},
		{"r--p", "/usr/lib/libc.so.6", false},
		{"r-xp", "/usr/bin/provider.test", false},
		{"---p", "", false},
		{"-w-p", "", false},
	} {
		if got := sweptMapping(tc.perms, tc.path); got != tc.want {
			t.Errorf("sweptMapping(%q, %q) = %v, want %v", tc.perms, tc.path, got, tc.want)
		}
	}
}

// TestReadLen pins the per-read length against a remaining span wider than an
// int, which converted first would go negative on a 32-bit target.
func TestReadLen(t *testing.T) {
	for _, tc := range []struct {
		off, hi uintptr
		max     int
		want    int
	}{
		{0, 16, 2048, 16},
		{0x1000, 0x1800, 2048, 2048},
		{0, math.MaxInt32 + 1, 2048, 2048},
		{0, ^uintptr(0), 1 << 20, 1 << 20},
		{1, ^uintptr(0), 7, 7},
	} {
		if got := readLen(tc.off, tc.hi, tc.max); got != tc.want {
			t.Errorf("readLen(%#x, %#x, %d) = %d, want %d", tc.off, tc.hi, tc.max, got, tc.want)
		}
	}
}

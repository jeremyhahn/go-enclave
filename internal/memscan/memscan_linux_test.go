// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package memscan

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strings"
	"testing"
)

// scratch returns a scan buffer of the shape Find builds, small enough that
// the boundary-straddling case below actually crosses a chunk.
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
	if found, err := mappingContains(bytes.NewReader(region), 0, uintptr(len(region)), needle, buf); err != nil || !found {
		t.Fatal("control: the scan did not find a needle that is there, so the wipe assertion below is vacuous")
	}
	if !AllZero(buf) {
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

	if found, err := mappingContains(bytes.NewReader(region), 0, uintptr(len(region)), needle, buf); err != nil || found {
		t.Fatal("the scan reported a match in a region that does not contain the needle")
	}
	if !AllZero(buf) {
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
	if found, _ := mappingContains(r, 0, regionLen, needle, buf); found {
		t.Fatal("reported a match the reader never produced")
	}
	// The reader must have been asked for the whole region, or the zero buffer
	// below proves nothing.
	if r.calls == 0 || r.requests[0] != regionLen {
		t.Fatalf("mappingContains called the reader %d time(s) with requests %v; want a first request of %d bytes", r.calls, r.requests, regionLen)
	}
	if !AllZero(buf) {
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
			if found, err := mappingContains(bytes.NewReader(region), 0, uintptr(len(region)), needle, buf); err != nil || !found {
				t.Errorf("a needle at offset %d, straddling the %d-byte read boundary at %d, was missed",
					start, read, (start/read+1)*read)
			}
		})
	}
}

// TestMappingContainsStopsAtAnOffsetReadAtCannotTake pins the overflow guard:
// an address above math.MaxInt64 is never handed to ReadAt as a negative
// offset, which would scan the wrong region.
func TestMappingContainsStopsAtAnOffsetReadAtCannotTake(t *testing.T) {
	if math.MaxUint64 != uint64(^uintptr(0)) {
		t.Skip("a 32-bit uintptr cannot exceed math.MaxInt64; the guard is unreachable here")
	}
	r := &scratchingReader{}
	maxOffset := uint64(math.MaxInt64) // a variable, so the conversion below compiles on 32-bit targets
	lo := uintptr(maxOffset + 1)
	found, err := mappingContains(r, lo, lo+4096, []byte("x"), scratch(64, 1))
	if found {
		t.Fatal("reported a match above the largest file offset")
	}
	if err == nil {
		t.Error("an address ReadAt cannot take was reported as scanned clean")
	}
	if r.calls != 0 {
		t.Errorf("ReadAt was called %d time(s) for an address above math.MaxInt64", r.calls)
	}
}

// TestMappingContainsStopsWhenAReadCannotAdvance pins that a read no longer
// than the overlap ends the scan rather than looping on the same offset.
func TestMappingContainsStopsWhenAReadCannotAdvance(t *testing.T) {
	r := &shortReader{n: 3}
	found, err := mappingContains(r, 0, 4096, []byte("needle"), scratch(64, len("needle")))
	if found {
		t.Fatal("reported a match the reader never produced")
	}
	if err == nil {
		t.Error("a read that cannot advance left the region unscanned but was reported clean")
	}
	if r.calls != 1 {
		t.Errorf("ReadAt was called %d times; a read that cannot advance must end the scan", r.calls)
	}
}

// eofReader serves data from address 0. A read that ends at the end of data
// returns a full count together with io.EOF, which io.ReaderAt permits. When
// failAt is positive, a read that would cross it returns the bytes up to failAt
// (fewer than asked) and io.ErrUnexpectedEOF instead.
type eofReader struct {
	data   []byte
	failAt int
}

func (r *eofReader) ReadAt(p []byte, off int64) (int, error) {
	if r.failAt > 0 && int(off)+len(p) > r.failAt {
		return copy(p, r.data[off:r.failAt]), io.ErrUnexpectedEOF
	}
	n := copy(p, r.data[off:])
	if int(off)+n >= len(r.data) {
		return n, io.EOF
	}
	return n, nil
}

func TestMappingContainsAcceptsAFullFinalReadWithEOF(t *testing.T) {
	needle := []byte("needle")
	region := make([]byte, 200)
	copy(region[len(region)-len(needle):], needle)
	found, err := mappingContains(&eofReader{data: region}, 0, uintptr(len(region)), needle, scratch(64, len(needle)))
	if err != nil || !found {
		t.Errorf("needle in the final chunk, read with io.EOF: found, err = %v, %v; want true, nil", found, err)
	}
	clean := make([]byte, 200)
	found, err = mappingContains(&eofReader{data: clean}, 0, uintptr(len(clean)), needle, scratch(64, len(needle)))
	if err != nil || found {
		t.Errorf("clean region, final chunk read with io.EOF: found, err = %v, %v; want false, nil", found, err)
	}
}

func TestFindRefusesAShortReadWithAnError(t *testing.T) {
	needle := []byte("needle")
	maps := "00000000-000000c8 rw-p 00000000 00:00 0 [anon: x]\n"
	mem := &eofReader{data: make([]byte, 200), failAt: 100}
	_, err := find(maps, mem, needle, 0x100000, scratch(64, len(needle)))
	if !errors.Is(err, ErrUnreadableMapping) {
		t.Errorf("a short read with an error before the end of the mapping: find = %v, want ErrUnreadableMapping", err)
	}
	ok := &eofReader{data: make([]byte, 200)}
	if hits, err := find(maps, ok, needle, 0x100000, scratch(64, len(needle))); err != nil || len(hits) != 0 {
		t.Errorf("a full final read with io.EOF: find = %v, %v; want no hits, nil", hits, err)
	}
}

// shortReader returns n zero bytes and no error on every call.
type shortReader struct {
	n, calls int
}

func (r *shortReader) ReadAt(p []byte, _ int64) (int, error) {
	r.calls++
	clear(p[:r.n])
	return r.n, nil
}

// addressSpace is an io.ReaderAt over regions placed at fake addresses; a read
// outside every region fails, as /proc/self/mem does for an unmapped address.
type addressSpace map[int64][]byte

func (a addressSpace) ReadAt(p []byte, off int64) (int, error) {
	for base, data := range a {
		if off >= base && off < base+int64(len(data)) {
			return bytes.NewReader(data).ReadAt(p, off-base)
		}
	}
	return 0, io.ErrUnexpectedEOF
}

// TestFindSweepsOnlyWhatCanHoldACopy drives the sweep over a synthetic maps
// listing: a hit is reported by its line, and every line that must not be
// swept, or is the needle's home, is passed over even when it holds the
// needle.
func TestFindSweepsOnlyWhatCanHoldACopy(t *testing.T) {
	needle := []byte("the-needle")
	page := func(withNeedle bool) []byte {
		b := make([]byte, 0x1000)
		if withNeedle {
			copy(b[0x800:], needle)
		}
		return b
	}
	mem := addressSpace{
		0x10000: page(true),  // anonymous: swept, a hit
		0x20000: page(true),  // the home mapping: excluded
		0x30000: page(true),  // read-only file text: not swept
		0x40000: page(true),  // unreadable: not swept
		0x50000: page(false), // anonymous, no needle: a miss
		0x60000: page(true),  // writable file mapping: swept, a hit
	}
	maps := strings.Join([]string{
		"10000-11000 rw-p 00000000 00:00 0",
		"20000-21000 rw-p 00000000 00:00 0",
		"30000-31000 r--p 00000000 08:01 1234 /usr/lib/libc.so.6",
		"40000-41000 ---p 00000000 00:00 0",
		"50000-51000 rw-p 00000000 00:00 0 [anon: Go: heap]",
		"60000-61000 rw-s 00000000 08:01 99 /var/tmp/shared file",
		"70000-70000 rw-p 00000000 00:00 0",
		"zzzz-71000 rw-p 00000000 00:00 0",
		"truncated line",
		"",
	}, "\n")
	buf := scratch(0x400, len(needle))

	got, err := find(maps, mem, needle, 0x20800, buf)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	want := []string{"10000-11000 rw-p 00000000 00:00 0", "60000-61000 rw-s 00000000 08:01 99 /var/tmp/shared file"}
	if !slices.Equal(got, want) {
		t.Errorf("find = %q, want %q", got, want)
	}
	if !AllZero(buf) {
		t.Error("the scan buffer holds what it read after the sweep returned")
	}
}

// TestFindFailsClosedOnAnUnreadableMapping pins that a swept mapping the
// reader refuses is a typed error, not a clean result, and that a hit found
// before it is not reported alongside it.
func TestFindFailsClosedOnAnUnreadableMapping(t *testing.T) {
	needle := []byte("the-needle")
	mem := addressSpace{0x10000: make([]byte, 0x1000)} // 0x20000 is unmapped: reads fail
	maps := "10000-11000 rw-p 00000000 00:00 0\n20000-21000 rw-p 00000000 00:00 0 [anon: x]\n"

	hits, err := find(maps, mem, needle, 0, scratch(0x400, len(needle)))
	var ue *UnreadableMappingError
	if !errors.Is(err, ErrUnreadableMapping) || !errors.As(err, &ue) || ue.Mapping != "20000-21000 rw-p 00000000 00:00 0 [anon: x]" {
		t.Fatalf("find = %v, %v; want an UnreadableMappingError for the second mapping", hits, err)
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("the read failure is not reachable through Unwrap: %v", err)
	}
	if hits != nil {
		t.Errorf("hits = %q alongside an error", hits)
	}
}

// TestFindExcusesOnlyKernelMappings pins the one rule for mappings the sweep
// may leave unread: the kernel's [vvar] and [vsyscall], which /proc/self/mem
// refuses and which hold no process data.
func TestFindExcusesOnlyKernelMappings(t *testing.T) {
	needle := []byte("the-needle")
	mem := addressSpace{0x10000: make([]byte, 0x1000)}
	for _, path := range []string{"[vvar]", "[vvar_vclock]", "[vsyscall]"} {
		maps := "10000-11000 rw-p 00000000 00:00 0\n20000-21000 r--p 00000000 00:00 0 " + path + "\n"
		if _, err := find(maps, mem, needle, 0, scratch(0x400, len(needle))); err != nil {
			t.Errorf("%s: find = %v, want the kernel mapping excused", path, err)
		}
	}
	maps := "10000-11000 rw-p 00000000 00:00 0\n20000-21000 r--p 00000000 00:00 0 [vdso]\n"
	if _, err := find(maps, mem, needle, 0, scratch(0x400, len(needle))); !errors.Is(err, ErrUnreadableMapping) {
		t.Errorf("[vdso]: find = %v, want ErrUnreadableMapping: it is readable and must be swept", err)
	}
}

// TestFindFailsClosedOnAnEmptySweep pins that a sweep that read nothing is an
// error: nothing scanned, so "no hits" proves nothing.
func TestFindFailsClosedOnAnEmptySweep(t *testing.T) {
	needle := []byte("the-needle")
	mem := addressSpace{0x10000: make([]byte, 0x1000)}
	for name, tc := range map[string]struct {
		maps string
		home uintptr
	}{
		"empty listing":         {"", 0},
		"nothing sweepable":     {"30000-31000 r--p 00000000 08:01 1234 /usr/lib/libc.so.6\n40000-41000 ---p 00000000 00:00 0\n", 0},
		"only the home mapping": {"10000-11000 rw-p 00000000 00:00 0\n", 0x10800},
		"only a kernel mapping": {"20000-21000 r--p 00000000 00:00 0 [vvar]\n", 0},
	} {
		hits, err := find(tc.maps, mem, needle, tc.home, scratch(0x400, len(needle)))
		if !errors.Is(err, ErrEmptySweep) || hits != nil {
			t.Errorf("%s: find = %v, %v; want ErrEmptySweep", name, hits, err)
		}
	}
}

// TestFindFindsAndExcludesHome is the end-to-end check on the real address
// space: a needle held in a live heap slice is findable, and passing its own
// address as home excludes its mapping.
func TestFindFindsAndExcludesHome(t *testing.T) {
	needle := make([]byte, 48)
	for i := range needle {
		needle[i] = byte(i*7 + 13)
	}

	// Both preconditions fail rather than skip: reading one's own /proc/self
	// needs no privilege on Linux, and a sweep that cannot find a live needle
	// would make the exclusion assertion vacuous.
	hits, err := Find(needle, 0)
	if err != nil {
		t.Fatalf("cannot sweep process memory: %v (the runner must mount /proc and allow a process to read "+
			"its own /proc/self/maps and /proc/self/mem)", err)
	}
	if len(hits) == 0 {
		t.Fatal("the sweep found no mapping holding a needle that is live in this process; it cannot see " +
			"anything here and the exclusion assertion would be vacuous")
	}

	home, err := Addr(needle)
	if err != nil {
		t.Fatalf("Addr: %v", err)
	}
	excluded, err := Find(needle, home)
	if err != nil {
		t.Fatalf("Find: %v", err)
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

// TestFindRefusesAnEmptyNeedle pins that an empty needle, which every mapping
// contains, is refused rather than reported as resident everywhere.
func TestFindRefusesAnEmptyNeedle(t *testing.T) {
	if hits, err := Find(nil, 0); err == nil || hits != nil {
		t.Errorf("Find(nil) = %v, %v; want nil and an error", hits, err)
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

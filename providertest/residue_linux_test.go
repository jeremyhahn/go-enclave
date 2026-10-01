// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

package providertest

import (
	"bytes"
	"fmt"
	"io"
	"testing"
)

// scratch returns a scan buffer of the shape residueMappings builds, small
// enough that the boundary-straddling case below actually crosses a chunk.
func scratch(chunk, needleLen int) []byte {
	return make([]byte, chunk+needleLen-1)
}

// TestMappingContainsWipesTheScanBuffer is the test the per-mapping wipe exists
// for, and it exists because a mutant of that wipe SURVIVED the whole suite:
// whether the hazard bites depends on the order the kernel lists mappings in,
// so no end-to-end test can be relied on to catch it.
//
// The buffer ends a scan holding whatever it last read. Carried into the next
// mapping — which is where the buffer itself lives, since it is an ordinary
// heap allocation — the instrument finds its own copy of the needle and reports
// a leak that exists nowhere but inside itself. The same self-contamination was
// independently hit in a parent-scans-child probe during the PR #45 review,
// where the counts climbed 2 -> 6 -> 10 across successive scans.
func TestMappingContainsWipesTheScanBuffer(t *testing.T) {
	needle := []byte("needle-that-must-not-ride-along-into-the-next-mapping")
	region := make([]byte, 4096)
	copy(region[1000:], needle)

	buf := scratch(2048, len(needle))

	// CONTROL: the scan found it, so the buffer demonstrably held it. Without
	// this an all-zero buffer afterwards would prove nothing — a scan that read
	// nothing leaves a zero buffer too.
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
// mapping with no match still leaves the buffer full of that mapping's bytes,
// and the needle can be among them when the needle's OWN mapping is the one
// being excluded — which is the normal case, not an edge one.
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
// wipe. mappingContains wipes only the prefix it handed to ReadAt (#90), and
// that prefix has to be the REQUEST, not the count ReadAt returned: a reader
// may scribble over all of p and report one byte. A bound taken from the
// returned count would leave the scribbled tail — a copy of whatever the
// reader read — for the next mapping's scan to find.
func TestMappingContainsWipesWhatTheReaderUsedAsScratch(t *testing.T) {
	needle := []byte("not present")
	buf := scratch(2048, len(needle))
	const regionLen = 1500 // shorter than buf: the request is the region, not the buffer

	r := &scratchingReader{fill: 0x5C}
	if mappingContains(r, 0, regionLen, needle, buf) {
		t.Fatal("reported a match the reader never produced")
	}
	// The reader must have run and been asked for the whole region — or the
	// zero buffer below proves nothing: a mappingContains that returned
	// before reading would leave it zero too.
	if r.calls == 0 || r.requests[0] != regionLen {
		t.Fatalf("mappingContains called the reader %d time(s) with requests %v; want a first request of %d bytes", r.calls, r.requests, regionLen)
	}
	if !allZero(buf) {
		t.Errorf("the reader's scratch survived mappingContains; first non-zero byte at index %d of the %d "+
			"requested", bytes.IndexFunc(buf, func(r rune) bool { return r != 0 }), regionLen)
	}
}

// TestMappingContainsSpansChunkBoundaries pins the overlap. A fixed-window scan
// misses a needle straddling a boundary, and a sweep that silently cannot see
// half the possible placements is the vacuous-instrument failure this package
// is built to avoid.
func TestMappingContainsSpansChunkBoundaries(t *testing.T) {
	needle := []byte("straddle-me-across-the-boundary")
	const chunk = 512
	buf := scratch(chunk, len(needle))
	// A read fills the WHOLE buffer, so the boundary a needle has to straddle
	// is at a multiple of len(buf) — not of chunk. Getting that wrong is how
	// the first version of this test passed with the overlap deleted: every
	// placement it chose happened to land inside one read either way, so it
	// asserted nothing about the overlap at all.
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

// TestParseMapsHeader pins the line recognizer the home exclusion depends on:
// a header that fails to parse is a mapping silently skipped, and a bad range
// is a mapping wrongly excluded.
//
// The expected bounds are uint64 so the table compiles on 32-bit targets too.
// There a 64-bit address does not fit a uintptr and must be REJECTED, not
// narrowed into a different range, so a row's expected ok is its wantOK and
// "the bound fits this platform's uintptr" — and the 32-bit row keeps every
// platform asserting at least one successful parse.
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
// its own mapping as home excludes it. Without the exclusion every legitimate
// copy would read as a leak, which is how the conformance suite's positive
// control fails when it is removed.
func TestResidueMappingsFindsAndExcludesHome(t *testing.T) {
	needle := bytes.Repeat([]byte{0x00}, 48)
	for i := range needle {
		needle[i] = byte(i*7 + 13)
	}

	// Both preconditions FAIL rather than skip (#90). Reading /proc/self/maps
	// and /proc/self/mem of one's own process needs no privilege on Linux, so
	// an error here means the runner's /proc is missing or filtered; and a
	// sweep that cannot find a needle live in this very process cannot see
	// anything, so the exclusion assertion below would be vacuous.
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

// TestSuiteCatchesAProviderThatRetainsACopy is the deliberate-leak control the
// whole design is ranked around.
//
// It lives in the Linux file because the residue sweep is the only instrument
// for retention by COPY and it exists only here; on every other platform the
// suite reports the sweep as not run, which
// TestResidueSweepReportsItselfNotRunOffLinux (residue_other_test.go) pins. A
// build constraint, not a runtime skip (#90).
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

// TestEqualBytes pins the comparison the residue check's recovery control
// rests on: a recovery of the wrong LENGTH is not the key, whatever its
// prefix holds.
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

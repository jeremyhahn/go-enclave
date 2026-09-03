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
func TestParseMapsHeader(t *testing.T) {
	tests := []struct {
		name   string
		line   string
		lo, hi uintptr
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
		{name: "empty", line: "", wantOK: false},
		{name: "no range separator", line: "7f0c00000000 rw-p", wantOK: false},
		{name: "not hexadecimal", line: "zzzz-7f0c00021000 rw-p", wantOK: false},
		{name: "no fields", line: "7f0c00000000-7f0c00021000", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lo, hi, ok := parseMapsHeader(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("parseMapsHeader ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && (lo != tc.lo || hi != tc.hi) {
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

	hits, err := residueMappings(needle, 0)
	if err != nil {
		t.Skipf("cannot sweep process memory here: %v", err)
	}
	if len(hits) == 0 {
		t.Skip("the sweep found no mapping holding a needle that is live in this process; it cannot see " +
			"anything here and this assertion would be vacuous")
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

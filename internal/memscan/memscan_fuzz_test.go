// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package memscan

import (
	"strings"
	"testing"
)

// mapsLineSeeds are real-shaped /proc/self/maps lines and malformed variants,
// shared by the parser and the walk fuzzers as seeds.
var mapsLineSeeds = []string{
	"c000000000-c004000000 rw-p 00000000 00:00 0 ",
	"c000000000-c004000000 rw-p 00000000 00:00 0 \t\t\t\t [anon: Go: heap]",
	"55d0c8a3e000-55d0c8a5f000 rw-p 00000000 00:00 0                          [heap]",
	"7ffd1b9c0000-7ffd1b9e1000 rw-p 00000000 00:00 0                          [stack]",
	"7ffd1b9f6000-7ffd1b9f8000 r-xp 00000000 00:00 0                          [vdso]",
	"7ffd1b9f2000-7ffd1b9f6000 r--p 00000000 00:00 0                          [vvar]",
	"ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]",
	"7f0c00000000-7f0c00021000 rw-p 00000000 00:00 0",
	"7f0c4a000000-7f0c4a001000 rw-s 00000000 00:01 4096                       /memfd:secret (deleted)",
	"7f0c4b000000-7f0c4b001000 r--p 00000000 08:01 1234                       /tmp/key file (deleted)",
	"7f0c4c000000-7f0c4c200000 r-xp 00000000 08:01 5678                       /usr/lib/libc.so.6",
	"08048000-08049000 r-xp 00000000 08:01 1234 /bin/true",
	"ffffffffffffffff-ffffffffffffffff rw-p 00000000 00:00 0",
	"10000000000000000-10000000000000001 rw-p 00000000 00:00 0",
	"00000000000000000000001000-0000000000000000000002000 rw-p 00000000 00:00 0",
	"2000-1000 rw-p 00000000 00:00 0",
	"1000-1000 rw-p 00000000 00:00 0",
	"0x1000-0x2000 rw-p 00000000 00:00 0",
	"1_000-2_000 rw-p 00000000 00:00 0",
	"+1000-2000 rw-p 00000000 00:00 0",
	"1000--2000 rw-p 00000000 00:00 0",
	"-2000 rw-p 00000000 00:00 0",
	"1000- rw-p 00000000 00:00 0",
	"1000-2000\trw-p 00000000 00:00 0",
	" 1000-2000 rw-p 00000000 00:00 0",
	"7f0c00000000 rw-p",
	"7f0c00000000-7f0c00021000",
	"Size:                  4 kB",
	"",
}

// refMapsHeader is an independent reading of a maps header: the text before
// the first space is two runs of hexadecimal digits joined by one '-', and
// each run fits a uintptr. It does not order the bounds.
func refMapsHeader(line string) (lo, hi uint64, ok bool) {
	first, _, cut := strings.Cut(line, " ")
	if !cut {
		return 0, 0, false
	}
	l, r, cut := strings.Cut(first, "-")
	if !cut {
		return 0, 0, false
	}
	lo, lok := refHex(l)
	hi, hok := refHex(r)
	return lo, hi, lok && hok
}

// refHex parses a non-empty run of hexadecimal digits that fits a uintptr.
func refHex(s string) (uint64, bool) {
	limit := uint64(^uintptr(0))
	var v uint64
	for _, c := range []byte(s) {
		var d byte
		switch {
		case c >= '0' && c <= '9':
			d = c - '0'
		case c >= 'a' && c <= 'f':
			d = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			d = c - 'A' + 10
		default:
			return 0, false
		}
		if v > limit>>4 {
			return 0, false
		}
		v = v<<4 | uint64(d)
	}
	return v, s != "" && v <= limit
}

// FuzzParseMapsHeader pins the maps-line recognizer: it never panics, it
// accepts exactly the lines whose header is two hexadecimal bounds that fit a
// uintptr with the low bound not above the high one, and it returns those
// bounds.
func FuzzParseMapsHeader(f *testing.F) {
	for _, line := range mapsLineSeeds {
		f.Add(line)
	}

	f.Fuzz(func(t *testing.T, line string) {
		lo, hi, ok := ParseMapsHeader(line)
		rlo, rhi, rok := refMapsHeader(line)
		want := rok && rlo <= rhi
		if ok != want {
			t.Fatalf("ParseMapsHeader(%q) ok = %v, want %v", line, ok, want)
		}
		if ok && (uint64(lo) != rlo || uint64(hi) != rhi) {
			t.Fatalf("ParseMapsHeader(%q) = %#x-%#x, want %#x-%#x", line, lo, hi, rlo, rhi)
		}
	})
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package memscan

import "testing"

func TestAllZero(t *testing.T) {
	for _, tc := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"nil", nil, true},
		{"zeros", make([]byte, 33), true},
		{"a non-zero first byte", []byte{1, 0, 0}, false},
		{"a non-zero last byte", []byte{0, 0, 0x80}, false},
	} {
		if got := AllZero(tc.b); got != tc.want {
			t.Errorf("AllZero(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestAddrLandsOnTheFirstElement pins that Addr is the address of b[0], not of
// the slice header: the home exclusion compares it with mapping bounds.
func TestAddrLandsOnTheFirstElement(t *testing.T) {
	if _, err := Addr(nil); err == nil {
		t.Error("Addr(nil) = nil error; an empty slice has no first element")
	}
	b := make([]byte, 64)
	base, err := Addr(b)
	if err != nil {
		t.Fatalf("Addr: %v", err)
	}
	if base == 0 {
		t.Error("Addr returned 0 for a live slice")
	}
	next, err := Addr(b[1:])
	if err != nil {
		t.Fatalf("Addr: %v", err)
	}
	if next != base+1 {
		t.Errorf("Addr(b[1:]) = %#x, want Addr(b)+1 = %#x", next, base+1)
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
		{name: "an smaps field line", line: "Size:                  4 kB", wantOK: false},
		{name: "no range separator", line: "7f0c00000000 rw-p", wantOK: false},
		{name: "not hexadecimal", line: "zzzz-7f0c00021000 rw-p", wantOK: false},
		{name: "high bound not hexadecimal", line: "7f0c00000000-zzzz rw-p", wantOK: false},
		{name: "low bound above high bound", line: "7f0c00021000-7f0c00000000 rw-p", wantOK: false},
		{name: "no fields", line: "7f0c00000000-7f0c00021000", wantOK: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			wantOK := tc.wantOK && tc.hi <= uint64(^uintptr(0))
			lo, hi, ok := ParseMapsHeader(tc.line)
			if ok != wantOK {
				t.Fatalf("ParseMapsHeader ok = %v, want %v", ok, wantOK)
			}
			if ok && (uint64(lo) != tc.lo || uint64(hi) != tc.hi) {
				t.Errorf("ParseMapsHeader = %#x-%#x, want %#x-%#x", lo, hi, tc.lo, tc.hi)
			}
		})
	}
}

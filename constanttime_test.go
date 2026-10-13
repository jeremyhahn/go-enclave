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
	"testing"
)

func TestWipe(t *testing.T) {
	b := []byte("scrub")
	Wipe(b)
	for i, c := range b {
		if c != 0 {
			t.Errorf("byte %d = %d, want 0", i, c)
		}
	}
}

func TestCopyConstantTime_CopiesTheShorterLength(t *testing.T) {
	tests := []struct {
		name     string
		dst, src []byte
		want     []byte
	}{
		{"equal lengths", make([]byte, 3), []byte("abc"), []byte("abc")},
		{"short src", []byte("xyz"), []byte("a"), []byte("ayz")},
		{"short dst", make([]byte, 2), []byte("abc"), []byte("ab")},
		{"empty src", []byte("xyz"), nil, []byte("xyz")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copyConstantTime(tt.dst, tt.src)
			if !bytes.Equal(tt.dst, tt.want) {
				t.Errorf("dst = %q, want %q", tt.dst, tt.want)
			}
		})
	}
}

func TestEqualConstantTime(t *testing.T) {
	tests := []struct {
		x, y []byte
		want bool
	}{
		{[]byte("same"), []byte("same"), true},
		{[]byte("same"), []byte("sane"), false},
		{[]byte("same"), []byte("sam"), false},
		{nil, []byte{}, true},
	}
	for _, tt := range tests {
		if got := equalConstantTime(tt.x, tt.y); got != tt.want {
			t.Errorf("equalConstantTime(%q, %q) = %v, want %v", tt.x, tt.y, got, tt.want)
		}
	}
}

// FuzzConstantTime checks the constant-time helpers differentially:
// equalConstantTime must agree with bytes.Equal, and copyConstantTime with
// copy, on every pair of inputs, unequal lengths included.
func FuzzConstantTime(f *testing.F) {
	f.Add([]byte("same"), []byte("same"))
	f.Add([]byte("same"), []byte("sane"))
	f.Add([]byte("same"), []byte("sam"))
	f.Add([]byte{}, []byte("abc"))
	f.Add([]byte("abc"), []byte{})
	f.Fuzz(func(t *testing.T, x, y []byte) {
		if got, want := equalConstantTime(x, y), bytes.Equal(x, y); got != want {
			t.Fatalf("equalConstantTime(%q, %q) = %v, bytes.Equal = %v", x, y, got, want)
		}
		if !equalConstantTime(x, bytes.Clone(x)) {
			t.Fatalf("equalConstantTime(%q, its copy) = false", x)
		}

		got, want := bytes.Clone(x), bytes.Clone(x)
		copyConstantTime(got, y)
		copy(want, y)
		if !bytes.Equal(got, want) {
			t.Fatalf("copyConstantTime(%q, %q) left %q, copy leaves %q", x, y, got, want)
		}
	})
}

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

// Package memscan is the one sweep of this process's own memory: it reads
// every mapping that can hold a runtime copy of key material through
// /proc/self/mem and reports the ones a needle is resident in. The root
// package's Linux tests and providertest's residue check both prove with it
// that a secret left no copy behind.
//
// It imports nothing from the module, so the root package's own tests can use
// it without an import cycle.
package memscan

import (
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

var errEmptySlice = errors.New("memscan: cannot take the address of an empty slice")

// AllZero reports whether every byte of b is zero: the check that a wipe
// reached all of it.
func AllZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// Addr returns the address of a slice's first element, the home a sweep
// excludes. It goes through the %p verb so the package does not import unsafe.
func Addr(b []byte) (uintptr, error) {
	if len(b) == 0 {
		return 0, errEmptySlice
	}
	var addr uint64
	if _, err := fmt.Sscanf(fmt.Sprintf("%p", b), "0x%x", &addr); err != nil {
		return 0, fmt.Errorf("memscan: parsing slice address: %w", err)
	}
	return uintptr(addr), nil
}

// ParseMapsHeader recognizes a /proc/self/maps or /proc/self/smaps header line
// ("7f0c…-7f0c… rw-p …") and returns its bounds; any other smaps line
// ("Size:   4 kB") fails the hex parse. The bounds are parsed at
// bits.UintSize, so on a 32-bit target a value that does not fit is reported
// unparsable rather than narrowed.
func ParseMapsHeader(line string) (lo, hi uintptr, ok bool) {
	first, _, cut := strings.Cut(line, " ")
	if !cut {
		return 0, 0, false
	}
	l, r, cut := strings.Cut(first, "-")
	if !cut {
		return 0, 0, false
	}
	lv, err := strconv.ParseUint(l, 16, bits.UintSize)
	if err != nil {
		return 0, 0, false
	}
	rv, err := strconv.ParseUint(r, 16, bits.UintSize)
	if err != nil {
		return 0, 0, false
	}
	return uintptr(lv), uintptr(rv), true
}

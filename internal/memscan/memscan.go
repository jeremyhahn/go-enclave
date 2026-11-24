// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

// Package memscan sweeps this process's own memory for a needle through /proc/self/mem; it imports nothing from the module.
package memscan

import (
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

var errEmptySlice = errors.New("memscan: cannot take the address of an empty slice")

// Result is what a sweep found.
type Result struct {
	// Hits are the /proc/self/maps lines of the mappings that hold the needle.
	Hits []string
	// GuardPages counts the pages the sweep skipped because
	// /proc/self/pagemap proved them kernel guard pages (PM_GUARD_REGION),
	// which hold no data. Every other unreadable page fails the sweep.
	GuardPages int
}

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

// ParseMapsHeader returns the bounds of a /proc/self/maps or smaps header line; ok is false for any other line.
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
	if err != nil || lv > rv {
		return 0, 0, false
	}
	return uintptr(lv), uintptr(rv), true
}

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
	"io"
	"math"
	"math/bits"
	"os"
	"strconv"
	"strings"

	enclave "github.com/jeremyhahn/go-enclave"
)

// sweepSupported reports that this platform can sweep its own address space.
const sweepSupported = true

// sweepUnsupportedReason is unused on Linux.
const sweepUnsupportedReason = ""

// residueMappings returns the /proc/self/maps lines of every swept mapping
// (see sweptMapping) that contains needle, excluding the one that contains
// home. The scan buffer is wiped after every mapping (see mappingContains).
func residueMappings(needle []byte, home uintptr) ([]string, error) {
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return nil, err
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return nil, err
	}
	defer func() { _ = mem.Close() }()

	const chunk = 1 << 20
	// Chunks overlap by len(needle)-1 so a needle straddling a boundary is
	// found.
	overlap := len(needle) - 1
	buf := make([]byte, chunk+overlap)
	defer enclave.Wipe(buf)

	var hits []string
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if !sweptMapping(fields[1], strings.Join(fields[5:], " ")) {
			continue
		}
		lo, hi, ok := parseMapsHeader(line)
		if !ok || hi <= lo {
			continue
		}
		if home >= lo && home < hi {
			continue
		}

		if mappingContains(mem, lo, hi, needle, buf) {
			hits = append(hits, strings.TrimSpace(line))
		}
	}
	return hits, nil
}

// mappingContains reports whether the region [lo, hi) of mem contains needle,
// reading it through the caller's scratch buffer.
//
// It wipes buf before returning. Otherwise buf carries a copy of the needle
// into the scan of a later mapping, possibly the one buf lives in, and the
// sweep reports its own copy as a leak. It wipes exactly the largest prefix it
// handed to ReadAt (io.ReaderAt may scribble on all of it even on a short
// read); the rest of buf was never written. Wiping the whole 1 MiB buffer per
// mapping makes the sweep too slow under the race detector.
func mappingContains(mem io.ReaderAt, lo, hi uintptr, needle, buf []byte) bool {
	used := 0
	defer func() { enclave.Wipe(buf[:used]) }()

	overlap := len(needle) - 1
	for off := lo; off < hi; {
		if uint64(off) > math.MaxInt64 {
			// Unreachable in practice, but ReadAt takes a signed offset and a
			// wrap would scan the wrong region. Widened to uint64 so it compiles
			// on 32-bit targets, where it is always false.
			return false
		}
		n := readLen(off, hi, len(buf))
		used = max(used, n)
		read, rerr := mem.ReadAt(buf[:n], int64(off))
		if read > 0 && bytes.Contains(buf[:read], needle) {
			return true
		}
		if rerr != nil {
			return false
		}
		if read <= overlap {
			return false
		}
		off += uintptr(read - overlap)
	}
	return false
}

// readLen is the length of one read of [off, hi) into a buffer of size max.
// The span is compared as a uintptr because on a 32-bit target it can exceed
// math.MaxInt32.
func readLen(off, hi uintptr, max int) int {
	if rem := hi - off; rem < uintptr(max) {
		return int(rem)
	}
	return max
}

// sweptMapping reports whether a mapping with these /proc/self/maps
// permissions and pathname can hold a runtime copy of key material, and so is
// swept.
func sweptMapping(perms, path string) bool {
	if !strings.HasPrefix(perms, "r") {
		return false // unreadable: /proc/self/mem refuses it
	}
	switch {
	case path == "" || strings.HasPrefix(path, "["):
		return true // anonymous, whether or not the kernel named it
	case len(perms) > 1 && perms[1] == 'w':
		return true // any writable mapping: private file copy, shared file, /dev/zero
	case strings.HasPrefix(path, "/memfd:"), strings.HasPrefix(path, "/dev/shm/"),
		strings.HasPrefix(path, "/SYSV"), strings.HasSuffix(path, " (deleted)"):
		return true // memory-backed or unlinked: written through a descriptor, whatever this mapping's permissions
	default:
		return false // read-only view of a file on disk: program text and rodata, the file's own bytes
	}
}

// parseMapsHeader recognizes a /proc/self/maps line ("7f0c…-7f0c… rw-p …") and
// returns its bounds. They are parsed at bits.UintSize, so on a 32-bit target a
// value that does not fit is reported unparsable rather than narrowed.
func parseMapsHeader(line string) (lo, hi uintptr, ok bool) {
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

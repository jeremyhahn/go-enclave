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
	"io"
	"math"
	"os"
	"strings"
)

// Supported reports that this platform can sweep its own address space.
const Supported = true

// UnsupportedReason is empty on Linux.
const UnsupportedReason = ""

// chunk is the most one read of /proc/self/mem asks for.
const chunk = 1 << 20

var errEmptyNeedle = errors.New("memscan: an empty needle matches everywhere")

// Find returns the /proc/self/maps lines of every swept mapping (see
// sweptMapping) that contains needle, excluding the one that contains home.
// Pass 0 for home to exclude nothing. The scan buffer is wiped after every
// mapping (see mappingContains).
//
// It needs an unfiltered /proc that lets a process read its own
// /proc/self/maps and /proc/self/mem; a caller fails rather than skips without
// one. Callers must keep their needles out of plain heap or stack locals
// (generate into locked pages, compare inside borrows), or the sweep finds
// those copies.
func Find(needle []byte, home uintptr) ([]string, error) {
	if len(needle) == 0 {
		return nil, errEmptyNeedle
	}
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return nil, err
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return nil, err
	}
	defer func() { _ = mem.Close() }()
	return find(string(maps), mem, needle, home, make([]byte, chunk+len(needle)-1)), nil
}

// find is Find over a maps listing and the memory it describes, reading
// through buf. Chunks overlap by len(needle)-1 so a needle straddling a read
// boundary is found, so buf must be longer than that.
func find(maps string, mem io.ReaderAt, needle []byte, home uintptr, buf []byte) []string {
	var hits []string
	for _, line := range strings.Split(maps, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if !sweptMapping(fields[1], strings.Join(fields[5:], " ")) {
			continue
		}
		lo, hi, ok := ParseMapsHeader(line)
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
	return hits
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
	// clear is a memclr of memory buf still references, so it is not elided.
	defer func() { clear(buf[:used]) }()

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

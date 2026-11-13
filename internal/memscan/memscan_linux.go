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

var (
	errOffsetRange = errors.New("address above the largest file offset")
	errNoProgress  = errors.New("read returned no more than the overlap")
)

// Find returns the /proc/self/maps lines of every swept mapping (see
// sweptMapping) that contains needle, excluding the one that contains home.
// Pass 0 for home to exclude nothing. The scan buffer is wiped after every
// mapping (see mappingContains).
//
// It fails closed: a swept mapping it cannot read returns an
// *UnreadableMappingError (ErrUnreadableMapping), and a sweep that read nothing
// returns ErrEmptySweep. Only the kernel's own [vvar] and [vsyscall] regions
// are excused. Callers must not discard these errors.
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
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return nil, err
	}
	defer func() { _ = mem.Close() }()
	readMaps := func() (string, error) {
		maps, err := os.ReadFile("/proc/self/maps")
		return string(maps), err
	}
	return sweep(readMaps, mem, needle, home, make([]byte, chunk+len(needle)-1))
}

// sweepAttempts bounds how many maps listings one sweep reads.
const sweepAttempts = 3

// sweep runs find over a fresh maps listing. A mapping the runtime unmaps
// between the listing and its read fails that read; it held nothing then, so
// sweep lists the mappings again and reads what is there. A mapping that is
// still unreadable after sweepAttempts listings fails the sweep closed.
func sweep(readMaps func() (string, error), mem io.ReaderAt, needle []byte, home uintptr, buf []byte) ([]string, error) {
	var err error
	for range sweepAttempts {
		var maps string
		if maps, err = readMaps(); err != nil {
			return nil, err
		}
		var hits []string
		if hits, err = find(maps, mem, needle, home, buf); !errors.Is(err, ErrUnreadableMapping) {
			return hits, err
		}
	}
	return nil, err
}

// find is Find over a maps listing and the memory it describes, reading
// through buf. Chunks overlap by len(needle)-1 so a needle straddling a read
// boundary is found, so buf must be longer than that.
//
// It fails closed. A swept mapping that cannot be read in full returns an
// *UnreadableMappingError (ErrUnreadableMapping), and a sweep that read no
// mapping returns ErrEmptySweep, so neither can pass as a clean result. The one
// excuse is a kernelMapping, which holds no process data. A home mapping is
// excluded without being read, and does not count as read.
func find(maps string, mem io.ReaderAt, needle []byte, home uintptr, buf []byte) ([]string, error) {
	var hits []string
	read := 0
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
		if kernelMapping(strings.Join(fields[5:], " ")) {
			continue
		}
		found, err := mappingContains(mem, lo, hi, needle, buf)
		if err != nil {
			return nil, &UnreadableMappingError{Mapping: strings.TrimSpace(line), Err: err}
		}
		read++
		if found {
			hits = append(hits, strings.TrimSpace(line))
		}
	}
	if read == 0 {
		return nil, ErrEmptySweep
	}
	return hits, nil
}

// kernelMapping reports whether a mapping is one the kernel provides to every
// process and /proc/self/mem refuses to read ([vvar], [vsyscall]). They hold
// no process data, so they are the only mappings the sweep may leave unread.
// The vDSO is readable and is swept like any other.
func kernelMapping(path string) bool {
	switch path {
	case "[vvar]", "[vvar_vclock]", "[vsyscall]":
		return true
	}
	return false
}

// mappingContains reports whether the region [lo, hi) of mem contains needle,
// reading it through the caller's scratch buffer. A region it could not read
// in full, because a read failed or made no progress, is an error rather than
// a miss; a match found before the failure is still a match.
//
// It wipes buf before returning. Otherwise buf carries a copy of the needle
// into the scan of a later mapping, possibly the one buf lives in, and the
// sweep reports its own copy as a leak. It wipes exactly the largest prefix it
// handed to ReadAt (io.ReaderAt may scribble on all of it even on a short
// read); the rest of buf was never written. Wiping the whole 1 MiB buffer per
// mapping makes the sweep too slow under the race detector.
func mappingContains(mem io.ReaderAt, lo, hi uintptr, needle, buf []byte) (bool, error) {
	used := 0
	// clear is a memclr of memory buf still references, so it is not elided.
	defer func() { clear(buf[:used]) }()

	overlap := len(needle) - 1
	for off := lo; off < hi; {
		if uint64(off) > math.MaxInt64 {
			// Unreachable in practice, but ReadAt takes a signed offset and a
			// wrap would scan the wrong region. Widened to uint64 so it compiles
			// on 32-bit targets, where it is always false.
			return false, errOffsetRange
		}
		n := readLen(off, hi, len(buf))
		used = max(used, n)
		read, rerr := mem.ReadAt(buf[:n], int64(off))
		if read > 0 && contains(buf[:read], needle) {
			return true, nil
		}
		if off+uintptr(read) >= hi {
			// The read reached the end of the region: all of it was scanned. An
			// io.ReaderAt may return a full count with io.EOF, which is not a failure.
			return false, nil
		}
		if rerr != nil {
			return false, rerr
		}
		if read <= overlap {
			return false, errNoProgress
		}
		off += uintptr(read - overlap)
	}
	return false, nil
}

// contains reports whether hay holds needle without ever holding more than
// one byte of the needle in a register. bytes.Contains keeps a short needle
// whole in registers while it compares, and a signal that lands then has
// the kernel save those registers, byte-exact, into a frame on the thread's
// signal stack, which lives in the Go heap and is never cleared: the sweep
// would plant the copy it looks for, and a later sweep would report it.
// IndexByte broadcasts only the needle's first byte; the compare below
// loads one byte at a time.
func contains(hay, needle []byte) bool {
	last := len(hay) - len(needle)
	for i := 0; i <= last; i++ {
		j := bytes.IndexByte(hay[i:last+1], needle[0])
		if j < 0 {
			return false
		}
		i += j
		if equalByByte(hay[i:i+len(needle)], needle) {
			return true
		}
	}
	return false
}

// equalByByte reports whether a and b, of b's length, hold the same bytes,
// comparing one byte at a time (see contains).
func equalByByte(a, b []byte) bool {
	for k := range b {
		if a[k] != b[k] {
			return false
		}
	}
	return true
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

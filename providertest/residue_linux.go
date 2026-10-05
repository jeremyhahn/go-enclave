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

// sweepUnsupportedReason is unused on Linux; it exists so the two platform
// files present the same surface.
const sweepUnsupportedReason = ""

// residueMappings returns the /proc/self/maps lines of every swept mapping
// (see [sweptMapping]) that contains needle, excluding the one that contains
// home.
//
// Anonymous mappings are swept WHETHER OR NOT the kernel named them: the Go
// runtime labels its heap `[anon: Go: heap]`. So are memfd, /dev/shm,
// /dev/zero, unlinked and every writable file-backed mapping, any of which a
// provider can keep a key in.
//
// The scan buffer is wiped after EVERY mapping, not merely on return. Scanning
// the needle's own legitimate mapping copies the needle into an ordinary heap
// buffer; if that buffer is still holding it when the sweep reaches the mapping
// the buffer itself lives in, the instrument finds its own copy and reports a
// leak that does not exist. Wiping on return alone leaves that hole open for
// the remainder of a single scan, and whether it bites depends on nothing more
// principled than which mapping the kernel lists first.
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
	// Chunks overlap by len(needle)-1 so a needle straddling a boundary is not
	// missed — the failure mode of a fixed-window scan.
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
		// The needle's own mapping is where it legitimately lives.
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
// IT WIPES buf BEFORE RETURNING, and that is the whole reason this is a
// function rather than an inline loop. buf ends a scan holding a copy of the
// last thing it read, needle included; carried into the next mapping, the
// instrument reads its own buffer and reports a leak that exists nowhere but
// inside itself. Wiping only when the whole sweep returns leaves that hole open
// for every mapping after the needle's own, and whether it bites depends on
// nothing more principled than the order the kernel lists mappings in — which
// is why the wipe is here, where it can be tested, instead of at the end of a
// loop where a mutant of it survives.
//
// It wipes exactly the prefix of buf this call handed to ReadAt — the largest
// request it made — and no more. io.ReaderAt may use ALL of the slice it is
// given as scratch even when it reports a short read, so the bound is what was
// requested, not what was returned; and nothing past the largest request was
// written at all, so the rest of buf is still the zeroes the previous call
// left. The bound is not an optimization of taste. buf is a full 1 MiB chunk
// and most mappings are a few pages, so wiping all of it per mapping cost a
// sweep hundreds of megabytes of writes, and under the race detector — where
// every byte Wipe stores is an instrumented write — that made each conformance
// run take seconds and pushed the package past go test's default timeout in
// the repository's own -race -cpu=1,2,8 gate (#90).
func mappingContains(mem io.ReaderAt, lo, hi uintptr, needle, buf []byte) bool {
	used := 0
	defer func() { enclave.Wipe(buf[:used]) }()

	overlap := len(needle) - 1
	for off := lo; off < hi; {
		if uint64(off) > math.MaxInt64 {
			// Unreachable on every architecture this builds for — a user-space
			// address lives far below 2^63 — but ReadAt takes a SIGNED offset,
			// and a wrap here would silently scan a wildly different region and
			// report a clean sweep of it. The comparison is widened to uint64
			// because on a 32-bit target uintptr cannot hold math.MaxInt64 and
			// the untyped constant would not compile; there the guard is simply
			// always false, which is the truth.
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
// The span is compared as a uintptr: on a 32-bit target it can exceed
// math.MaxInt32, and converted first it would go negative.
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
// returns its bounds.
//
// The bounds are parsed at the width of a uintptr (bits.UintSize, which every
// Go port keeps equal to the pointer size), not a fixed 64: on a 32-bit target
// a value that does not fit is not an address in this process, and narrowing it
// would silently scan — or exclude as home — a different range than the line
// names. It is reported as unparsable instead.
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

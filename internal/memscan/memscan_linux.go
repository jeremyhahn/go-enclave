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
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
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

// Find returns the maps lines of every swept mapping containing needle, except home's; it fails closed on unreadable mappings.
func Find(needle []byte, home uintptr) ([]string, error) {
	r, err := Sweep(needle, home)
	return r.Hits, err
}

// Sweep is Find, and also reports how many guard pages it skipped.
func Sweep(needle []byte, home uintptr) (Result, error) {
	if len(needle) == 0 {
		return Result{}, errEmptyNeedle
	}
	proc, closeProc, err := openProc()
	if err != nil {
		return Result{}, err
	}
	defer closeProc()
	readMaps := func() (string, error) {
		maps, err := os.ReadFile("/proc/self/maps")
		return string(maps), err
	}
	return resweep(readMaps, proc, needle, home, make([]byte, chunk+len(needle)-1))
}

// openProc opens /proc/self/mem and, for guard-page checks, /proc/self/pagemap.
// A pagemap that cannot be opened is recorded, not returned: it fails the
// sweep only if an unreadable page needs it.
func openProc() (procMem, func(), error) {
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return procMem{}, nil, err
	}
	proc := procMem{mem: mem, pageSize: uintptr(os.Getpagesize())}
	pagemap, err := os.Open("/proc/self/pagemap")
	if err != nil {
		proc.pagemapErr = err
		return proc, func() { _ = mem.Close() }, nil
	}
	proc.pagemap = pagemap
	return proc, func() { _ = mem.Close(); _ = pagemap.Close() }, nil
}

// sweepAttempts bounds how many maps listings one sweep reads.
const sweepAttempts = 3

// resweep relists and rereads after a mapping vanishes, up to sweepAttempts; a hit is always kept.
func resweep(readMaps func() (string, error), mem io.ReaderAt, needle []byte, home uintptr, buf []byte) (Result, error) {
	var res Result
	seen := map[string]bool{}
	var err error
	for range sweepAttempts {
		var maps string
		if maps, err = readMaps(); err != nil {
			break
		}
		var r Result
		r, err = sweep(maps, mem, needle, home, buf)
		res.GuardPages = r.GuardPages
		for _, m := range r.Hits {
			if !seen[m] {
				seen[m] = true
				res.Hits = append(res.Hits, m)
			}
		}
		if !errors.Is(err, ErrUnreadableMapping) {
			break
		}
	}
	// A hit any attempt made is a finding, whatever a later attempt saw.
	if len(res.Hits) > 0 {
		return res, nil
	}
	if err != nil {
		return Result{}, err
	}
	return res, nil
}

// find is Find over a maps listing, reading through buf in overlapping chunks; it fails closed.
func find(maps string, mem io.ReaderAt, needle []byte, home uintptr, buf []byte) ([]string, error) {
	r, err := sweep(maps, mem, needle, home, buf)
	return r.Hits, err
}

// sweep is find, and also counts the guard pages it skipped.
func sweep(maps string, mem io.ReaderAt, needle []byte, home uintptr, buf []byte) (Result, error) {
	var r Result
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
		found, guards, err := mappingScan(mem, lo, hi, needle, buf)
		if err != nil {
			ue := &UnreadableMappingError{Mapping: strings.TrimSpace(line), Err: err, Kernel: kernelRelease()}
			probeMapping(mem, lo, hi, ue)
			return r, ue
		}
		read++
		r.GuardPages += guards
		if found {
			r.Hits = append(r.Hits, strings.TrimSpace(line))
		}
	}
	if read == 0 {
		return Result{}, ErrEmptySweep
	}
	return r, nil
}

// kernelMapping reports whether a mapping is [vvar] or [vsyscall], the only mappings left unread.
func kernelMapping(path string) bool {
	switch path {
	case "[vvar]", "[vvar_vclock]", "[vsyscall]":
		return true
	}
	return false
}

// mappingContains reports whether [lo, hi) of mem contains needle, and wipes the part of buf it used.
func mappingContains(mem io.ReaderAt, lo, hi uintptr, needle, buf []byte) (bool, error) {
	found, _, err := mappingScan(mem, lo, hi, needle, buf)
	return found, err
}

// mappingScan is mappingContains, and also counts the guard pages it skipped
// before it returned.
func mappingScan(mem io.ReaderAt, lo, hi uintptr, needle, buf []byte) (bool, int, error) {
	used, guards := 0, 0
	// clear is a memclr of memory buf still references, so it is not elided.
	defer func() { clear(buf[:used]) }()

	overlap := len(needle) - 1
	for off := lo; off < hi; {
		if uint64(off) > math.MaxInt64 {
			// Unreachable in practice, but ReadAt takes a signed offset and a
			// wrap would scan the wrong region. Widened to uint64 so it compiles
			// on 32-bit targets, where it is always false.
			return false, guards, errOffsetRange
		}
		n := readLen(off, hi, len(buf))
		used = max(used, n)
		read, rerr := mem.ReadAt(buf[:n], int64(off))
		if read > 0 && contains(buf[:read], needle) {
			return true, guards, nil
		}
		if off+uintptr(read) >= hi {
			// The read reached the end of the region: all of it was scanned. An
			// io.ReaderAt may return a full count with io.EOF, which is not a failure.
			return false, guards, nil
		}
		if rerr != nil {
			// A guard page holds no data and can hold no needle, so the
			// scan restarts after it with no overlap.
			end, err := skipGuard(mem, off+uintptr(read), rerr)
			if err != nil {
				return false, guards, err
			}
			guards++
			off = end
			continue
		}
		if read <= overlap {
			return false, guards, errNoProgress
		}
		off += uintptr(read - overlap)
	}
	return false, guards, nil
}

// pmGuardRegion is PM_GUARD_REGION, bit 58 of a pagemap entry (Linux 6.15+).
const pmGuardRegion = 1 << 58

// guardPages is a memory reader that can say whether a page is a guard
// region. procMem is the one Find uses.
type guardPages interface {
	io.ReaderAt
	// guardRegion reports whether the page holding addr is a guard region,
	// and the address where that page ends.
	guardRegion(addr uintptr) (end uintptr, guard bool, err error)
}

// procMem reads /proc/self/mem and looks up pages in /proc/self/pagemap. A
// pagemap that could not be opened is kept as pagemapErr, so the sweep fails
// only if it meets a page it must ask about.
type procMem struct {
	mem        io.ReaderAt
	pagemap    io.ReaderAt
	pagemapErr error
	pageSize   uintptr
}

func (p procMem) ReadAt(b []byte, off int64) (int, error) { return p.mem.ReadAt(b, off) }

// guardRegion reads the 64-bit, native-endian pagemap entry of the page
// holding addr, at offset (addr / page size) * 8.
func (p procMem) guardRegion(addr uintptr) (uintptr, bool, error) {
	entry, err := p.pagemapEntry(addr)
	if err != nil {
		return 0, false, err
	}
	return (addr/p.pageSize + 1) * p.pageSize, entry&pmGuardRegion != 0, nil
}

// pagemapEntry returns the raw /proc/self/pagemap entry of the page holding addr.
func (p procMem) pagemapEntry(addr uintptr) (uint64, error) {
	if p.pagemapErr != nil {
		return 0, p.pagemapErr
	}
	page := addr / p.pageSize
	if uint64(page) > math.MaxInt64/8 {
		// Unreachable for a real page size, but ReadAt takes a signed offset
		// and a wrap would read another page's entry. Widened to uint64 so it
		// compiles on 32-bit targets, where it is always false.
		return 0, errOffsetRange
	}
	var entry [8]byte
	if _, err := p.pagemap.ReadAt(entry[:], int64(page)*8); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint64(entry[:]), nil
}

// probeMapping records which pages of an unreadable mapping fail and are not guard pages.
func probeMapping(mem io.ReaderAt, lo, hi uintptr, e *UnreadableMappingError) {
	p, ok := mem.(procMem)
	if !ok || p.pageSize == 0 {
		return
	}
	var b [1]byte
	// clear is a memclr of memory b still references, so it is not elided.
	defer clear(b[:])
	// first <= a stops the walk if a wraps past the top of the address space,
	// and ReadAt takes a signed offset.
	first := lo &^ (p.pageSize - 1)
	for a := first; a >= first && a < hi && uint64(a) <= math.MaxInt64; a += p.pageSize {
		n, rerr := p.mem.ReadAt(b[:], int64(a))
		if n == len(b) {
			continue
		}
		entry, perr := p.pagemapEntry(a)
		if perr == nil && errors.Is(rerr, syscall.EIO) && entry&pmGuardRegion != 0 {
			e.GuardPages++
			continue
		}
		e.UnreadablePages++
		if len(e.Pages) < maxUnreadablePages {
			e.Pages = append(e.Pages, UnreadablePage{Addr: a, Pagemap: entry, PagemapErr: perr})
		}
	}
}

// kernelRelease is the running kernel's release, as uname -r prints it.
func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "unknown (uname: " + err.Error() + ")"
	}
	return unix.ByteSliceToString(u.Release[:])
}

// skipGuard lets a read step over a page only on EIO with PM_GUARD_REGION set.
func skipGuard(mem io.ReaderAt, addr uintptr, rerr error) (uintptr, error) {
	g, ok := mem.(guardPages)
	if !ok || !errors.Is(rerr, syscall.EIO) {
		return 0, rerr
	}
	end, guard, err := g.guardRegion(addr)
	if err != nil {
		return 0, errors.Join(rerr, err)
	}
	if !guard || end <= addr {
		return 0, rerr
	}
	return end, nil
}

// contains reports whether hay holds needle, never holding more than one needle byte in a register.
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

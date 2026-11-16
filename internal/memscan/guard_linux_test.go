// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package memscan

import (
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

const testPage = 0x1000

// guardedSpace serves data from address 0 the way /proc/self/mem does: a read
// copies up to the first page in bad and stops there, returning the bytes it
// copied and EIO wrapped in an *os.PathError, as os.File.ReadAt does.
type guardedSpace struct {
	data  []byte
	bad   map[int]bool // page indexes whose reads fail
	err   error        // the failure; syscall.EIO when nil
	reads int
}

func (g *guardedSpace) ReadAt(p []byte, off int64) (int, error) {
	g.reads++
	n := 0
	for n < len(p) && int(off)+n < len(g.data) {
		if g.bad[(int(off)+n)/testPage] {
			err := g.err
			if err == nil {
				err = syscall.EIO
			}
			return n, &os.PathError{Op: "read", Path: "/proc/self/mem", Err: err}
		}
		p[n] = g.data[int(off)+n]
		n++
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// pagemapOf builds a pagemap: one native-endian 64-bit entry per page of a
// pages-page region at address 0, with PM_GUARD_REGION set for guard pages and
// the present bit set for the others.
func pagemapOf(pages int, guard ...int) []byte {
	pm := make([]byte, 8*pages)
	for i := range pages {
		binary.NativeEndian.PutUint64(pm[8*i:], 1<<63)
	}
	for _, i := range guard {
		binary.NativeEndian.PutUint64(pm[8*i:], 1<<58)
	}
	return pm
}

// failingPagemap is a pagemap that cannot be read.
type failingPagemap struct{ calls int }

var errPagemap = errors.New("pagemap refused")

func (f *failingPagemap) ReadAt([]byte, int64) (int, error) {
	f.calls++
	return 0, errPagemap
}

func guarded(space *guardedSpace, pagemap io.ReaderAt) procMem {
	return procMem{mem: space, pagemap: pagemap, pageSize: testPage}
}

// TestMappingContainsSkipsAGuardPage pins the one excused read failure: EIO
// on a page the pagemap marks as a guard region. A needle before the guard
// page, after it, or after a run of them is still found, a clean region is
// clean, and buffers smaller and larger than a page give the same answers.
func TestMappingContainsSkipsAGuardPage(t *testing.T) {
	needle := []byte("the-needle")
	const pages = 6
	guards := []int{1, 3, 4}
	bad := map[int]bool{1: true, 3: true, 4: true}

	for _, chunk := range []int{0x300, 0x1000, 0x4000} {
		for _, at := range []int{-1, 0, testPage - len(needle), 2 * testPage, 3*testPage - len(needle), 5 * testPage, 6*testPage - len(needle)} {
			region := make([]byte, pages*testPage)
			if at >= 0 {
				copy(region[at:], needle)
			}
			space := &guardedSpace{data: region, bad: bad}
			buf := scratch(chunk, len(needle))
			found, err := mappingContains(guarded(space, readerOf(pagemapOf(pages, guards...))), 0, uintptr(len(region)), needle, buf)
			if err != nil || found != (at >= 0) {
				t.Errorf("chunk %#x, needle at %d: found, err = %v, %v; want %v, nil", chunk, at, found, err, at >= 0)
			}
			if !AllZero(buf) {
				t.Errorf("chunk %#x, needle at %d: the scan buffer was not wiped", chunk, at)
			}
		}
	}
}

// TestMappingContainsRestartsAfterAGuardPage pins that the scan restarts at
// the page after a guard page with no overlap: a needle cannot span the guard
// page, so bytes on either side of it never join into a match.
func TestMappingContainsRestartsAfterAGuardPage(t *testing.T) {
	needle := []byte("split-needle")
	region := make([]byte, 3*testPage)
	copy(region[testPage-6:], needle[:6])
	copy(region[2*testPage:], needle[6:])
	space := &guardedSpace{data: region, bad: map[int]bool{1: true}}
	found, err := mappingContains(guarded(space, readerOf(pagemapOf(3, 1))), 0, uintptr(len(region)), needle, scratch(0x800, len(needle)))
	if err != nil || found {
		t.Errorf("halves on either side of a guard page: found, err = %v, %v; want false, nil", found, err)
	}
}

// TestMappingContainsFailsOnEIOWithoutTheGuardBit pins that EIO alone excuses
// nothing: a page the pagemap does not mark as a guard region fails the scan.
func TestMappingContainsFailsOnEIOWithoutTheGuardBit(t *testing.T) {
	needle := []byte("the-needle")
	region := make([]byte, 3*testPage)
	copy(region[2*testPage:], needle)
	space := &guardedSpace{data: region, bad: map[int]bool{1: true}}
	found, err := mappingContains(guarded(space, readerOf(pagemapOf(3))), 0, uintptr(len(region)), needle, scratch(0x800, len(needle)))
	if found || !errors.Is(err, syscall.EIO) {
		t.Errorf("EIO on a page without PM_GUARD_REGION: found, err = %v, %v; want false, EIO", found, err)
	}
}

// TestMappingContainsFailsWhenThePagemapCannotBeRead pins that a guard page
// that cannot be confirmed is not skipped, and that both failures reach the
// caller.
func TestMappingContainsFailsWhenThePagemapCannotBeRead(t *testing.T) {
	needle := []byte("the-needle")
	region := make([]byte, 3*testPage)
	space := &guardedSpace{data: region, bad: map[int]bool{1: true}}
	pm := &failingPagemap{}
	found, err := mappingContains(guarded(space, pm), 0, uintptr(len(region)), needle, scratch(0x800, len(needle)))
	if found || !errors.Is(err, syscall.EIO) || !errors.Is(err, errPagemap) {
		t.Errorf("EIO with an unreadable pagemap: found, err = %v, %v; want false and both errors", found, err)
	}
	if pm.calls != 1 {
		t.Errorf("the pagemap was read %d times; want 1", pm.calls)
	}

	// A pagemap that ends before the page's entry cannot confirm it either.
	short := readerOf(pagemapOf(1))
	if _, err := mappingContains(guarded(&guardedSpace{data: region, bad: map[int]bool{1: true}}, short), 0, uintptr(len(region)), needle, scratch(0x800, len(needle))); !errors.Is(err, syscall.EIO) {
		t.Errorf("EIO with a pagemap too short for the page: err = %v; want EIO", err)
	}

	// Nor can a /proc/self/pagemap that could not be opened.
	unopened := procMem{mem: &guardedSpace{data: region, bad: map[int]bool{1: true}}, pagemapErr: errPagemap, pageSize: testPage}
	if _, err := mappingContains(unopened, 0, uintptr(len(region)), needle, scratch(0x800, len(needle))); !errors.Is(err, syscall.EIO) || !errors.Is(err, errPagemap) {
		t.Errorf("EIO with no pagemap: err = %v; want EIO and the open failure", err)
	}
}

// TestMappingContainsFailsOnOtherErrorsAtAGuardPage pins that only EIO is
// excused: any other failure on a guard page fails the scan without the
// pagemap being consulted.
func TestMappingContainsFailsOnOtherErrorsAtAGuardPage(t *testing.T) {
	needle := []byte("the-needle")
	region := make([]byte, 3*testPage)
	for _, rerr := range []error{syscall.EFAULT, syscall.EPERM, io.ErrUnexpectedEOF} {
		space := &guardedSpace{data: region, bad: map[int]bool{1: true}, err: rerr}
		pm := &countingReader{r: readerOf(pagemapOf(3, 1))}
		found, err := mappingContains(guarded(space, pm), 0, uintptr(len(region)), needle, scratch(0x800, len(needle)))
		if found || !errors.Is(err, rerr) {
			t.Errorf("%v on a guard page: found, err = %v, %v; want false, %v", rerr, found, err, rerr)
		}
		if pm.calls != 0 {
			t.Errorf("%v on a guard page: the pagemap was read %d times; want 0", rerr, pm.calls)
		}
	}
}

// TestMappingContainsFailsOnEIOFromAPlainReader pins that a reader with no
// pagemap behind it gets no excuse for EIO.
func TestMappingContainsFailsOnEIOFromAPlainReader(t *testing.T) {
	region := make([]byte, 3*testPage)
	space := &guardedSpace{data: region, bad: map[int]bool{1: true}}
	if _, err := mappingContains(space, 0, uintptr(len(region)), []byte("x"), scratch(0x800, 1)); !errors.Is(err, syscall.EIO) {
		t.Errorf("EIO from a reader without a pagemap: err = %v; want EIO", err)
	}
}

// TestFindSkipsGuardPagesAndReportsTheMapping pins the excuse through find: a
// mapping holding a guard page is swept, and a needle after the guard page
// is reported.
func TestFindSkipsGuardPagesAndReportsTheMapping(t *testing.T) {
	needle := []byte("the-needle")
	region := make([]byte, 4*testPage)
	copy(region[3*testPage:], needle)
	space := &guardedSpace{data: region, bad: map[int]bool{1: true}}
	maps := "00000000-00004000 rw-p 00000000 00:00 0\n"
	hits, err := find(maps, guarded(space, readerOf(pagemapOf(4, 1))), needle, 0x100000, scratch(0x800, len(needle)))
	if err != nil || len(hits) != 1 {
		t.Errorf("needle after a guard page: find = %q, %v; want the mapping, nil", hits, err)
	}
	_, err = find(maps, guarded(&guardedSpace{data: region, bad: map[int]bool{1: true}}, readerOf(pagemapOf(4))), needle, 0x100000, scratch(0x800, len(needle)))
	if !errors.Is(err, ErrUnreadableMapping) || !errors.Is(err, syscall.EIO) {
		t.Errorf("EIO without the guard bit: find err = %v; want ErrUnreadableMapping wrapping EIO", err)
	}
}

// TestProcMemReadsTheLivePagemap pins the decode against the running kernel:
// a page of this process's heap is not a guard region, and reading its entry
// succeeds. Any kernel with /proc/self/pagemap can run it.
func TestProcMemReadsTheLivePagemap(t *testing.T) {
	pm, err := os.Open("/proc/self/pagemap")
	if err != nil {
		t.Fatalf("open /proc/self/pagemap: %v", err)
	}
	defer func() { _ = pm.Close() }()
	page := make([]byte, os.Getpagesize())
	page[0] = 1
	p := procMem{pagemap: pm, pageSize: uintptr(os.Getpagesize())}
	addr := uintptr(unsafe.Pointer(&page[0]))
	end, guard, err := p.guardRegion(addr)
	if err != nil || guard {
		t.Fatalf("guardRegion(heap page) = %v, %v; want false, nil", guard, err)
	}
	if want := (addr/p.pageSize + 1) * p.pageSize; end != want {
		t.Errorf("guardRegion end = %#x; want %#x", end, want)
	}
}

// TestProcMemRefusesAPagemapOffsetAboveInt64 pins the overflow bound: a page
// index whose entry lies past math.MaxInt64 is never handed to ReadAt as a
// wrapped offset; it fails closed with errOffsetRange and no read. A 32-bit
// uintptr cannot reach the bound, so there the entry is read as usual.
func TestProcMemRefusesAPagemapOffsetAboveInt64(t *testing.T) {
	pm := &countingReader{r: readerOf(make([]byte, 8))}
	p := procMem{pagemap: pm, pageSize: 1}
	top := ^uintptr(0) // page index ^uintptr(0) with a one-byte page
	_, guard, err := p.guardRegion(top)
	if uint64(top) > math.MaxInt64/8 {
		if !errors.Is(err, errOffsetRange) || guard || pm.calls != 0 {
			t.Errorf("guardRegion(%#x) = %v, %v after %d reads; want errOffsetRange and no read", top, guard, err, pm.calls)
		}
		return
	}
	if pm.calls != 1 {
		t.Errorf("guardRegion(%#x) read the pagemap %d times; want 1", top, pm.calls)
	}
}

// countingReader counts the reads it passes through.
type countingReader struct {
	r     io.ReaderAt
	calls int
}

func (c *countingReader) ReadAt(p []byte, off int64) (int, error) {
	c.calls++
	return c.r.ReadAt(p, off)
}

func readerOf(b []byte) io.ReaderAt { return &byteReader{b} }

// guardKernel names the kernel the live guard test needs: MADV_GUARD_INSTALL
// came in Linux 6.13 and the pagemap PM_GUARD_REGION bit in 6.15.
const guardKernel = "Linux 6.15+ (MADV_GUARD_INSTALL from 6.13, PM_GUARD_REGION in /proc/self/pagemap from 6.15)"

// TestSweepSkipsALiveGuardRegion installs a real guard region with
// madvise(MADV_GUARD_INSTALL), plants a needle after it, and sweeps the
// mapping through /proc/self/mem: the sweep must read past the guard, find the
// needle and report exactly the guarded pages as skipped.
func TestSweepSkipsALiveGuardRegion(t *testing.T) {
	const pages, first, guards = 6, 1, 2 // pages first..first+guards-1 are guarded
	ps := os.Getpagesize()
	// A PROT_NONE page either side keeps the region in a VMA of its own.
	m, err := unix.Mmap(-1, 0, (pages+2)*ps, unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	defer func() { _ = unix.Munmap(m) }()
	region := m[ps : (pages+1)*ps]
	if err := unix.Mprotect(region, unix.PROT_READ|unix.PROT_WRITE); err != nil {
		t.Fatalf("mprotect: %v", err)
	}
	needle := []byte("memscan live guard-region needle")
	copy(region[(first+guards)*ps+17:], needle)
	if err := unix.Madvise(region[first*ps:(first+guards)*ps], unix.MADV_GUARD_INSTALL); err != nil {
		t.Fatalf("madvise(MADV_GUARD_INSTALL) = %v; this test needs %s", err, guardKernel)
	}

	proc, closeProc, err := openProc()
	if err != nil {
		t.Fatalf("openProc: %v", err)
	}
	defer closeProc()
	lo := uintptr(unsafe.Pointer(&region[0]))
	hi := lo + uintptr(len(region))
	for i := range pages {
		addr := lo + uintptr(i*ps)
		_, guard, err := proc.guardRegion(addr)
		if err != nil {
			t.Fatalf("guardRegion(page %d): %v", i, err)
		}
		if want := i >= first && i < first+guards; guard != want {
			t.Fatalf("pagemap PM_GUARD_REGION of page %d = %v, want %v; this test needs %s", i, guard, want, guardKernel)
		}
	}

	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatalf("read /proc/self/maps: %v", err)
	}
	var line string
	for _, l := range strings.Split(string(maps), "\n") {
		if a, b, ok := ParseMapsHeader(l); ok && a == lo {
			if b != hi {
				t.Fatalf("the region's mapping is %s, want it to end at %#x", l, hi)
			}
			line = l
		}
	}
	if line == "" {
		t.Fatalf("no mapping starts at the region, %#x", lo)
	}

	got, err := sweep(line, proc, needle, 0, make([]byte, chunk+len(needle)-1))
	if err != nil {
		t.Fatalf("sweep of the guarded mapping: %v", err)
	}
	if len(got.Hits) != 1 || got.GuardPages != guards {
		t.Fatalf("sweep of the guarded mapping = %d hit(s), %d guard page(s) skipped; want 1 hit and %d skipped",
			len(got.Hits), got.GuardPages, guards)
	}

	// The whole-process sweep finds the region too and counts its guard pages
	// among any other guard regions the process holds.
	all, err := Sweep(needle, 0)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if !slices.Contains(all.Hits, strings.TrimSpace(line)) || all.GuardPages < guards {
		t.Fatalf("Sweep = %d hit(s), %d guard page(s) skipped; want the region %q among the hits and at least %d skipped",
			len(all.Hits), all.GuardPages, line, guards)
	}
}

// byteReader is bytes.Reader's ReadAt without its other methods.
type byteReader struct{ b []byte }

func (r *byteReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.b)) {
		return 0, io.EOF
	}
	n := copy(p, r.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

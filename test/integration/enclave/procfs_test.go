// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package enclave_test

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	enclave "github.com/jeremyhahn/go-enclave"
)

// THE KERNEL'S SIDE OF THE STORY.
//
// Everything in this file reads /proc/self: what the kernel says this process
// has locked (VmLck), how each mapping is flagged (smaps VmFlags), and what the
// process's memory actually contains (/proc/self/mem). The suite's assertions
// about locking, core-dump exclusion, guard pages and residue are made against
// these readings, never against the library's own report of what it did.

// ---------------------------------------------------------------------------
// /proc/self/status

// statusField returns the value text of one /proc/self/status line.
func statusField(name string) (string, error) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if ok && k == name {
			return strings.TrimSpace(v), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("/proc/self/status has no %s line", name)
}

// vmLck returns the bytes the KERNEL accounts as locked by this process.
func vmLck(t *testing.T) int64 {
	t.Helper()
	v, err := statusField("VmLck")
	if err != nil {
		t.Fatalf("reading VmLck: %v", err)
	}
	kb, unit, _ := strings.Cut(v, " ")
	n, err := strconv.ParseInt(kb, 10, 64)
	if err != nil || unit != "kB" {
		t.Fatalf("VmLck = %q: want \"<n> kB\"", v)
	}
	return n * 1024
}

// ---------------------------------------------------------------------------
// /proc/self/smaps

// vma is one mapping as /proc/self/smaps reports it.
type vma struct {
	lo, hi uintptr
	perms  string // e.g. "r--p"
	name   string // pathname or [label], empty for an unnamed anonymous map
	flags  map[string]bool
	header string
}

func (v vma) size() int64 { return int64(v.hi - v.lo) }

func (v vma) String() string {
	fl := make([]string, 0, len(v.flags))
	for f := range v.flags {
		fl = append(fl, f)
	}
	return fmt.Sprintf("%s (VmFlags: %s)", v.header, strings.Join(fl, " "))
}

// readSmaps parses /proc/self/smaps into its mappings, in address order.
func readSmaps(t *testing.T) []vma {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/smaps")
	if err != nil {
		t.Fatalf("reading /proc/self/smaps: %v", err)
	}
	var out []vma
	for _, line := range strings.Split(string(raw), "\n") {
		if lo, hi, ok := parseMapsHeader(line); ok {
			fields := strings.Fields(line)
			v := vma{lo: lo, hi: hi, perms: fields[1], header: strings.TrimSpace(line)}
			if len(fields) > 5 {
				v.name = strings.Join(fields[5:], " ")
			}
			out = append(out, v)
			continue
		}
		if rest, ok := strings.CutPrefix(line, "VmFlags:"); ok {
			if len(out) == 0 {
				t.Fatalf("/proc/self/smaps: VmFlags before any mapping header")
			}
			cur := &out[len(out)-1]
			cur.flags = map[string]bool{}
			for _, f := range strings.Fields(rest) {
				cur.flags[f] = true
			}
		}
	}
	for _, v := range out {
		if v.flags == nil {
			t.Fatalf("/proc/self/smaps: no VmFlags line for %s; this kernel's smaps format is not the one this suite reads", v.header)
		}
	}
	if len(out) == 0 {
		t.Fatalf("/proc/self/smaps listed no mappings")
	}
	return out
}

// vmaAt returns the mapping containing addr and its index in maps.
func vmaAt(maps []vma, addr uintptr) (vma, int, bool) {
	for i, v := range maps {
		if addr >= v.lo && addr < v.hi {
			return v, i, true
		}
	}
	return vma{}, -1, false
}

// lockedVMAs returns every mapping the kernel flags VM_LOCKED ("lo").
func lockedVMAs(maps []vma) []vma {
	var out []vma
	for _, v := range maps {
		if v.flags["lo"] {
			out = append(out, v)
		}
	}
	return out
}

// parseMapsHeader recognizes a maps/smaps header line ("7f0c…-7f0c… rw-p …").
// A non-header smaps line ("Size:   4 kB") fails the hex parse.
func parseMapsHeader(line string) (lo, hi uintptr, ok bool) {
	first, _, cut := strings.Cut(line, " ")
	if !cut {
		return 0, 0, false
	}
	l, r, cut := strings.Cut(first, "-")
	if !cut {
		return 0, 0, false
	}
	lv, err := strconv.ParseUint(l, 16, 64)
	if err != nil {
		return 0, 0, false
	}
	rv, err := strconv.ParseUint(r, 16, 64)
	if err != nil || rv <= lv {
		return 0, 0, false
	}
	return uintptr(lv), uintptr(rv), true
}

// dataAddr returns the address of an enclave's first data byte. Only the
// ADDRESS leaves the borrow: no byte of the material is copied anywhere.
func dataAddr(t *testing.T, e *enclave.MemoryEnclave) uintptr {
	t.Helper()
	var addr uintptr
	if err := e.WithBytes(func(b []byte) error {
		addr = addrOfSlice(b)
		return nil
	}); err != nil {
		t.Fatalf("borrowing the enclave to locate it: %v", err)
	}
	return addr
}

// addrOfSlice returns the address of a slice's first byte.
func addrOfSlice(b []byte) uintptr { return uintptr(unsafe.Pointer(unsafe.SliceData(b))) }

// ---------------------------------------------------------------------------
// Residue: a needle that exists only where the test puts it

// needle is test material that NEVER exists in this process except where the
// test deliberately writes it.
//
// The obvious way to look for a value in memory is to hold a copy of it and
// search for that — and the copy is then exactly the residue the sweep finds,
// in every run. So the test never holds the value. It holds two random halves,
// key and mask, and the material is key XOR mask: it is written byte by byte
// into the destination (fill) and recognized byte by byte in place (matchAt),
// and is never assembled in a buffer of its own. Neither half matches the
// material, so neither half is ever a hit.
type needle struct {
	key, mask []byte
}

// needleLen is long enough that a chance match anywhere in a process's memory
// is not a possibility worth discussing (2^-512 per position).
const needleLen = 64

func newNeedle(t *testing.T) needle {
	t.Helper()
	n := needle{key: heapBytes(needleLen), mask: heapBytes(needleLen)}
	if _, err := io.ReadFull(rand.Reader, n.key); err != nil {
		t.Fatalf("generating a needle: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, n.mask); err != nil {
		t.Fatalf("generating a needle: %v", err)
	}
	return n
}

// heapBytes returns a zeroed slice that is guaranteed to live on the HEAP.
//
// Every caller buffer that holds the material must come from here. A
// constant-size `make` that the compiler proves does not escape is placed on
// the goroutine's STACK, and when that stack grows the runtime copies it —
// material included — to a new one and frees the old one without wiping it.
// The sweep then finds the stale copy and reports a leak the library under
// test never made (measured in this suite: two stray copies, 1 MiB apart, the
// signature of successive stack copies). Heap objects are never moved by Go's
// collector, so a wipe of a heap slice reaches the only copy there is.
// noinline keeps the allocation in a function whose result escapes.
//
//go:noinline
func heapBytes(n int) []byte { return make([]byte, n) }

// fill writes the material into dst, which must be exactly needleLen long.
func (n needle) fill(dst []byte) {
	for i := range dst {
		dst[i] = n.key[i] ^ n.mask[i]
	}
}

// matchAt reports whether buf holds the material starting at i.
func (n needle) matchAt(buf []byte, i int) bool {
	if len(buf)-i < needleLen {
		return false
	}
	for j := 0; j < needleLen; j++ {
		if buf[i+j]^n.mask[j] != n.key[j] {
			return false
		}
	}
	return true
}

// equals reports whether b is exactly the material.
func (n needle) equals(b []byte) bool { return len(b) == needleLen && n.matchAt(b, 0) }

// enclaveFromNeedle fills a fresh enclave with the material.
func enclaveFromNeedle(t *testing.T, n needle) *enclave.MemoryEnclave {
	t.Helper()
	e, err := enclave.NewMemoryEnclaveSized(needleLen)
	if err != nil {
		t.Fatalf("NewMemoryEnclaveSized: %v", err)
	}
	if err := e.WithBytes(func(b []byte) error { n.fill(b); return nil }); err != nil {
		t.Fatalf("filling the enclave: %v", err)
	}
	return e
}

// residueHit is one place the material was found.
type residueHit struct {
	addr    uintptr
	mapping string
}

// sweepScanned records what a sweep covered, so a negative result can be
// told apart from a sweep that looked at nothing.
type sweepScanned struct {
	mappings int
	bytes    int64
}

// sweep reads EVERY readable mapping of this process through /proc/self/mem
// and returns each address at which the material is found.
//
// Nothing readable is excluded — not the Go heap, not the stacks, not the
// race detector's memory, not file-backed mappings (the material is random, so
// unlike a literal needle it cannot appear in the binary's rodata) — with two
// exceptions, each of which can hold nothing the process put there:
//
//   - the kernel's [vvar]/[vvar_vclock]/[vsyscall] pages (timekeeping data no
//     user store can reach);
//   - the sweep's OWN scan buffer. Its only contents are bytes the sweep just
//     copied out of memory it has already scanned at their true addresses;
//     reading it back would report those as a second, phantom location
//     (measured: two "hits" in the Go heap, 512 KiB apart, before the library
//     had been called at all).
//
// Any other mapping that cannot be read FAILS the sweep: a mapping the sweep
// could not see is a place the material could be, and a clean result over a
// blind spot is a lie.
//
// The scan buffer is wiped after EVERY window, so no copy of the material
// outlives the comparison that needed it.
func sweep(t *testing.T, n needle) ([]residueHit, sweepScanned) {
	t.Helper()
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatalf("reading /proc/self/maps: %v", err)
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		t.Fatalf("opening /proc/self/mem: %v", err)
	}
	defer func() { _ = mem.Close() }()

	const chunk = 1 << 20
	buf := heapBytes(chunk + needleLen - 1)
	defer enclave.Wipe(buf)
	self := span{lo: addrOfSlice(buf), hi: addrOfSlice(buf) + uintptr(len(buf))}

	var hits []residueHit
	var scanned sweepScanned
	for _, line := range strings.Split(string(maps), "\n") {
		lo, hi, ok := parseMapsHeader(line)
		if !ok {
			continue
		}
		fields := strings.Fields(line)
		if !strings.HasPrefix(fields[1], "r") {
			continue
		}
		if len(fields) > 5 {
			switch fields[5] {
			case "[vvar]", "[vvar_vclock]", "[vsyscall]":
				continue
			}
		}
		for _, r := range (span{lo: lo, hi: hi}).minus(self) {
			found, err := scanRange(mem, r, n, buf)
			if err != nil {
				t.Fatalf("residue sweep could not read %s: %v — a mapping the sweep cannot see is a blind spot, so no clean result can be reported", strings.TrimSpace(line), err)
			}
			for _, a := range found {
				hits = append(hits, residueHit{addr: a, mapping: strings.TrimSpace(line)})
			}
			scanned.bytes += int64(r.hi - r.lo)
		}
		scanned.mappings++
	}
	if scanned.mappings == 0 {
		t.Fatalf("residue sweep scanned no mappings")
	}
	return hits, scanned
}

// span is a half-open address range [lo, hi).
type span struct{ lo, hi uintptr }

// minus returns the parts of s outside x.
func (s span) minus(x span) []span {
	if x.hi <= s.lo || x.lo >= s.hi {
		return []span{s}
	}
	var out []span
	if x.lo > s.lo {
		out = append(out, span{s.lo, x.lo})
	}
	if x.hi < s.hi {
		out = append(out, span{x.hi, s.hi})
	}
	return out
}

// scanRange returns every address in r holding the material, reading through
// buf and wiping it after every window.
func scanRange(mem io.ReaderAt, r span, n needle, buf []byte) ([]uintptr, error) {
	var found []uintptr
	overlap := needleLen - 1
	first := n.key[0] ^ n.mask[0]
	for off := r.lo; off < r.hi; {
		if uint64(off) > math.MaxInt64 {
			return nil, fmt.Errorf("address %#x does not fit a file offset", off)
		}
		want := len(buf)
		if remaining := r.hi - off; uint64(remaining) < uint64(want) {
			want = int(remaining)
		}
		got, err := mem.ReadAt(buf[:want], int64(off))
		// Candidates are found with bytes.IndexByte on the material's first
		// byte — one byte of it, which is no residue — and confirmed in place.
		// IndexByte is assembly, so under -race the scan is not instrumented
		// per byte; a plain loop made each sweep of ~400 MiB take seconds.
		for i := 0; i+needleLen <= got; i++ {
			j := bytes.IndexByte(buf[i:got-needleLen+1], first)
			if j < 0 {
				break
			}
			i += j
			if n.matchAt(buf[:got], i) {
				found = append(found, off+uintptr(i))
			}
		}
		clear(buf[:got]) // memclr: the buffer is read into again, so this cannot be elided
		if err != nil && !(errors.Is(err, io.EOF) && got == want) {
			return nil, err
		}
		if got < want {
			return nil, fmt.Errorf("short read at %#x: %d of %d bytes", off, got, want)
		}
		if off+uintptr(got) >= r.hi {
			break
		}
		if got <= overlap {
			return nil, fmt.Errorf("window at %#x too small to advance", off)
		}
		// Consecutive windows overlap by needleLen-1 bytes so material
		// straddling a boundary is seen; the next window starts at the first
		// position this one did not test, so nothing is reported twice.
		off += uintptr(got - overlap)
	}
	return found, nil
}

// requireHitsExactly fails unless the material was found at exactly the given
// addresses — each one, and nowhere else.
func requireHitsExactly(t *testing.T, what string, hits []residueHit, scanned sweepScanned, want ...uintptr) {
	t.Helper()
	wantSet := map[uintptr]bool{}
	for _, a := range want {
		wantSet[a] = true
	}
	gotSet := map[uintptr]bool{}
	for _, h := range hits {
		gotSet[h.addr] = true
		if !wantSet[h.addr] {
			t.Errorf("%s: material found at %#x in %s, which is not one of the %d place(s) it is meant to be",
				what, h.addr, h.mapping, len(want))
		}
	}
	for _, a := range want {
		if !gotSet[a] {
			t.Errorf("%s: material NOT found at %#x where it is known to be — the sweep cannot see it, so a clean result elsewhere would be vacuous", what, a)
		}
	}
	t.Logf("%s: %d hit(s) across %d readable mappings / %d MiB swept", what, len(hits), scanned.mappings, scanned.bytes>>20)
}

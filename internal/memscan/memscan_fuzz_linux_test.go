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
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
)

const (
	fuzzBase     = uintptr(0x10000) // address of the image's first byte
	fuzzSpan     = 0x1fff           // range offsets are masked to this, past the image's end
	fuzzImageMax = 0x1000
	fuzzNeedle   = 64
	fuzzRecord   = 6 // layout bytes per mapping
)

// fuzzPerms are permission fields, with whether the sweep may read them and
// whether they are writable.
var fuzzPerms = []struct {
	perms           string
	readable, write bool
}{
	{"rw-p", true, true},
	{"r--p", true, false},
	{"r-xp", true, false},
	{"rwxp", true, true},
	{"rw-s", true, true},
	{"r--s", true, false},
	{"---p", false, false},
	{"-w-p", false, true},
}

// Path kinds: what the sweep does with a readable mapping of that path.
const (
	pathAnon    = iota // swept whatever the permissions
	pathKernel         // never swept: the kernel refuses or faults it
	pathFile           // swept only when writable
	pathMemback        // swept whatever the permissions: memory-backed or unlinked
)

var fuzzPaths = []struct {
	path string
	kind int
}{
	{"", pathAnon},
	{"[heap]", pathAnon},
	{"[stack]", pathAnon},
	{"[vdso]", pathAnon},
	{"[anon: Go: heap]", pathAnon},
	{"[vvar]", pathKernel},
	{"[vvar_vclock]", pathKernel},
	{"[vsyscall]", pathKernel},
	{"/usr/lib/libc.so.6", pathFile},
	{"/dev/zero", pathFile},
	{"/usr/lib/deleted.so", pathFile},
	{"/memfd:secret (deleted)", pathMemback},
	{"/memfd:secret", pathMemback},
	{"/dev/shm/segment", pathMemback},
	{"/SYSV00000000", pathMemback},
	{"/tmp/key file (deleted)", pathMemback},
}

// fuzzMapping is one synthetic maps line and the walk's expected view of it.
type fuzzMapping struct {
	line   string
	lo, hi uintptr
	swept  bool // readable, not the kernel's, and the sweep covers its path
}

// decodeLayout turns layout bytes into maps lines, fuzzRecord bytes each: low
// and high offsets from fuzzBase, a permission index (its top bit moves the
// range to the top of the address space) and a path index (its top bit pads
// the path with tabs, as the kernel pads labeled anonymous mappings).
func decodeLayout(layout []byte) []fuzzMapping {
	var out []fuzzMapping
	for ; len(layout) >= fuzzRecord; layout = layout[fuzzRecord:] {
		a := uintptr(layout[0])<<8 | uintptr(layout[1])
		b := uintptr(layout[2])<<8 | uintptr(layout[3])
		base := fuzzBase
		if layout[4]&0x80 != 0 {
			base = ^uintptr(0) - fuzzSpan
		}
		lo, hi := base+a&fuzzSpan, base+b&fuzzSpan
		p := fuzzPerms[int(layout[4]&0x7f)%len(fuzzPerms)]
		path := fuzzPaths[int(layout[5]&0x7f)%len(fuzzPaths)]
		pad := " "
		if layout[5]&0x80 != 0 {
			pad = " \t\t\t\t "
		}
		line := fmt.Sprintf("%x-%x %s 00000000 00:00 0%s%s", lo, hi, p.perms, pad, path.path)
		swept := p.readable && path.kind != pathKernel &&
			(path.kind != pathFile || p.write)
		out = append(out, fuzzMapping{line: line, lo: lo, hi: hi, swept: swept})
	}
	return out
}

// boundedImage is an io.ReaderAt over image placed at fuzzBase that fails the
// test on any read outside the allowed ranges.
type boundedImage struct {
	t       *testing.T
	image   []byte
	allowed [][2]uintptr
}

func (m *boundedImage) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		m.t.Fatalf("ReadAt at negative offset %d", off)
	}
	start := uintptr(off)
	end := start + uintptr(len(p))
	inside := slices.ContainsFunc(m.allowed, func(r [2]uintptr) bool {
		return start >= r[0] && end <= r[1] && end >= start
	})
	if !inside {
		m.t.Fatalf("ReadAt [%#x, %#x) is outside every swept range", start, end)
	}
	if start < fuzzBase {
		return 0, io.EOF
	}
	return bytes.NewReader(m.image).ReadAt(p, int64(start-fuzzBase))
}

// clip returns the image bytes inside [lo, hi): the part a read can return.
func clip(image []byte, lo, hi uintptr) []byte {
	size := fuzzBase + uintptr(len(image))
	lo, hi = max(lo, fuzzBase), min(hi, size)
	if lo >= hi {
		return nil
	}
	return image[lo-fuzzBase : hi-fuzzBase]
}

// FuzzFind drives the maps walk over synthetic maps text and an image at a
// fixed base. The walk never panics, never reads outside a range it sweeps,
// and reports a line exactly when its swept range holds the needle; a range
// that runs past the image without the needle is an unreadable mapping. Free
// form maps text is walked too, with reads held to the ranges its lines list.
func FuzzFind(f *testing.F) {
	image := bytes.Repeat([]byte("residue-free "), 64)
	copy(image[0x200:], "SECRET")
	rec := func(a, b uint16, perm, path byte) []byte {
		return []byte{byte(a >> 8), byte(a), byte(b >> 8), byte(b), perm, path}
	}
	layouts := [][]byte{
		nil,
		rec(0, 0x400, 0, 0),       // anonymous, holds the needle
		rec(0, 0x400, 0, 0x81),    // [heap] padded with tabs
		rec(0x100, 0x203, 0, 2),   // [stack], needle cut by the end
		rec(0, 0x400, 1, 5),       // [vvar]: never swept
		rec(0, 0x400, 1, 8),       // read-only file: not swept
		rec(0, 0x400, 1, 15),      // deleted file: swept
		rec(0, 0x400, 6, 0),       // unreadable
		rec(0x400, 0x100, 0, 0),   // reversed bounds
		rec(0x300, 0x1800, 0, 11), // memfd past the image's end
		rec(0, 0x10, 0x80, 0),     // top of the address space
		append(rec(0, 0x400, 0, 0), rec(0x1f8, 0x210, 4, 13)...), // overlapping, shared
	}
	for _, l := range layouts {
		f.Add(l, image, []byte("SECRET"), uint16(0), uint8(0), strings.Join(mapsLineSeeds, "\n"))
		f.Add(l, image, []byte("SECRET"), uint16(0x10), uint8(200), "")
	}
	f.Add(rec(0, 0x1000, 0, 0), image, []byte("e-free r"), uint16(0x800), uint8(3), "10000-10400 rw-p 0 0 0")

	f.Fuzz(func(t *testing.T, layout, image, needle []byte, home uint16, extra uint8, raw string) {
		if len(needle) == 0 || len(needle) > fuzzNeedle {
			return
		}
		image = image[:min(len(image), fuzzImageMax)]
		maps := decodeLayout(layout)
		var homeAddr uintptr
		if home != 0 {
			homeAddr = fuzzBase + uintptr(home)&fuzzSpan
		}

		// The expected walk: lines in order, an unreadable range ends it.
		var (
			text      []string
			allowed   [][2]uintptr
			wantHits  []string
			wantErr   bool
			wantEmpty = true
		)
		for _, m := range maps {
			text = append(text, m.line)
			if wantErr || !m.swept || m.hi <= m.lo || (homeAddr >= m.lo && homeAddr < m.hi) {
				continue
			}
			allowed = append(allowed, [2]uintptr{m.lo, m.hi})
			wantEmpty = false
			switch {
			case bytes.Contains(clip(image, m.lo, m.hi), needle):
				wantHits = append(wantHits, strings.TrimSpace(m.line))
			case m.lo < fuzzBase || m.hi > fuzzBase+uintptr(len(image)):
				wantErr = true
			}
		}

		buf := make([]byte, len(needle)+int(extra))
		mem := &boundedImage{t: t, image: image, allowed: allowed}
		hits, err := find(strings.Join(text, "\n"), mem, needle, homeAddr, buf)
		var unreadable *UnreadableMappingError
		switch {
		case wantEmpty:
			if !errors.Is(err, ErrEmptySweep) {
				t.Fatalf("find over no swept range: err = %v, want ErrEmptySweep", err)
			}
		case wantErr:
			if !errors.As(err, &unreadable) {
				t.Fatalf("find past the image: err = %v, want an UnreadableMappingError", err)
			}
		case err != nil:
			t.Fatalf("find: %v", err)
		case !slices.Equal(hits, wantHits):
			t.Fatalf("find hits = %q, want %q", hits, wantHits)
		}
		if slices.ContainsFunc(buf, func(b byte) bool { return b != 0 }) {
			t.Fatalf("find left bytes in its buffer")
		}

		// Free-form text: no panic, and reads stay inside the ranges listed.
		var listed [][2]uintptr
		for _, line := range strings.Split(raw, "\n") {
			if lo, hi, ok := ParseMapsHeader(line); ok && lo < hi {
				listed = append(listed, [2]uintptr{lo, hi})
			}
		}
		// A buffer the image's size keeps a long list of wide ranges quick to walk.
		rawBuf := make([]byte, fuzzImageMax+len(needle)-1)
		_, _ = find(raw, &boundedImage{t: t, image: image, allowed: listed}, needle, 0, rawBuf)
	})
}

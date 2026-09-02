// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build linux

package enclave

import (
	"bytes"
	"os"
	"strings"
)

// Process-memory sweep, shared by every test that has to prove material is not
// resident somewhere it should not be.
//
// It lives in its own file because two PRs need it. PR #16 (SealedEnclave) grew
// it first, inline; this is the same code extracted so #18 can use it without a
// second copy drifting from the first. WHICHEVER OF #16 AND #18 MERGES SECOND
// MUST DELETE ITS COPY — the rebase will conflict here, and that conflict is the
// intended signal rather than an accident.
//
// The design is the corrected one, and the correction is worth keeping attached
// to the code: the first version skipped every kernel-NAMED mapping to avoid
// matching the test binary's own rodata, and the Go runtime NAMES its heap
// `[anon: Go: heap]`. Measured, that left one mapping swept and thirty skipped,
// so a plaintext copy retained on the heap forever went unnoticed by the one
// test written to catch it.
//
// The second lesson is the mirror of the first: an instrument can also SEE TOO
// MUCH — specifically, itself. The scan buffer holds copies of everything it
// reads, needle included, and an unwiped buffer becomes heap garbage a later
// sweep can find and misreport as a leak in the code under test. The first
// failure mode made the sweep blind; this one made it hallucinate. Both are
// documented at the code that fixes them.

// rangesOutside returns the matches that do not contain addr — that is, every
// copy of the needle other than the one the test is holding on purpose.
func rangesOutside(hits []string, addr uintptr) []string {
	var out []string
	for _, h := range hits {
		lo, hi, ok := parseSmapsHeader(h)
		if ok && addr >= lo && addr < hi {
			continue
		}
		out = append(out, h)
	}
	return out
}

// processMemoryFind returns the /proc/self/maps lines of every ANONYMOUS mapping
// that contains needle.
//
// File-backed mappings are excluded because the test binary's own rodata would
// match a literal needle in every run. Anonymous mappings are swept whether or
// not the kernel named them: the Go runtime labels its heap `[anon: Go: heap]`,
// and skipping named mappings is what made the first version of this sweep blind
// to the only place a leak could be.
func processMemoryFind(needle []byte) ([]string, error) {
	maps, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return nil, err
	}
	mem, err := os.Open("/proc/self/mem")
	if err != nil {
		return nil, err
	}
	defer mem.Close()

	const chunk = 1 << 20
	// Chunks overlap by len(needle)-1 so a needle straddling a boundary is not
	// missed — the failure mode of a fixed-window scan.
	overlap := len(needle) - 1
	buf := make([]byte, chunk+overlap)
	// THE SCAN BUFFER IS WIPED ON EVERY RETURN PATH, and this line is
	// load-bearing: without it the instrument PLANTS the very thing it looks
	// for. Scanning the needle's own (legitimate) mapping copies the needle
	// into buf — an ordinary heap allocation — and when buf becomes garbage
	// those bytes linger in the freed span until it is reused. A LATER sweep
	// then finds the EARLIER sweep's buffer and reports a heap residue that
	// never existed in the code under test. The same self-contamination shape
	// was independently hit and fixed in a parent-scans-child probe during
	// the PR #45 review, where the counts climbed 2->6->10 across scans.
	//
	// This buffer is ONE of two ways a sweep-based test was measured to smear
	// its own needle on PR #45. The other — a control copy in a
	// stack-allocatable local, stranded intact on the freed old stack when a
	// growth intervened between fill and wipe — cannot be fixed here or
	// anywhere, and retired that test's sweep formulation outright. (The
	// test in question left with the Decrypter/Signer adapter, split out to
	// issue #50; the forensics — hex-dump of the hit, addr2line on the
	// surrounding frames — are recorded there and on the PR #45 review.)
	// Tests that keep using this sweep must keep their needles out of plain
	// locals: generate into locked pages, hand copies only to callees that
	// take ownership and wipe (NewSealed), and compare from inside borrows.
	// The residency tests in this package hold to that; a new sweep-based
	// test that plants a bare heap or stack control copy will inherit the
	// flake.
	defer wipe(buf)

	var hits []string
	for _, line := range strings.Split(string(maps), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		if !strings.HasPrefix(fields[1], "r") {
			continue
		}
		// File-backed only: a pathname starts with '/'. Kernel labels like
		// [anon: Go: heap], [stack] and [heap] are anonymous and ARE swept.
		if len(fields) > 5 && strings.HasPrefix(fields[5], "/") {
			continue
		}
		lo, hi, ok := parseSmapsHeader(line)
		if !ok || hi <= lo {
			continue
		}

		for off := lo; off < hi; {
			n := chunk
			if remaining := int(hi - off); remaining < n {
				n = remaining
			}
			read, rerr := mem.ReadAt(buf[:n], int64(off))
			if read > 0 && bytes.Contains(buf[:read], needle) {
				hits = append(hits, strings.TrimSpace(line))
				break
			}
			if rerr != nil {
				break
			}
			if read <= overlap {
				break
			}
			off += uintptr(read - overlap)
		}
	}
	return hits, nil
}

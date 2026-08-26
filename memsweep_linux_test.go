// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-enclave.
//
// go-enclave is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

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

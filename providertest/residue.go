// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package providertest

import (
	"crypto/rand"
	"io"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// checkNoResidueAfterUnprotect is the residue sweep: the only instrument that
// can see a retained copy, which the spy cannot. It protects a needle that
// exists only in locked pages, recovers it into a second locked mapping, proves
// the sweep finds it there, wipes and destroys that mapping, and then requires
// the needle to appear nowhere in the process but its own mapping. Every
// comparison happens inside a borrow, so the suite never creates a heap copy of
// its own to find.
func checkNoResidueAfterUnprotect(r *report, cfg Config) {
	const property = "no copy of the key is findable in the process after Unprotect returns"

	if cfg.SkipResidueSweep != "" {
		r.note("providertest: residue sweep SKIPPED by Config.SkipResidueSweep — %q. "+
			"Retention by COPY is therefore unmeasured for this provider; only retention by reference was "+
			"checked, and the two are different defects", cfg.SkipResidueSweep)
		return
	}
	if !memscan.Supported {
		r.unmeasured(property, "residue sweep not run: %s. Retention by copy is unmeasured on this platform; "+
			"run the suite on Linux to measure it, or accept that with Config.SkipResidueSweep", memscan.UnsupportedReason)
		return
	}

	p, err := newProtector(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	// Generated in locked pages: a heap copy would be found by the sweep.
	needle, err := enclave.NewMemorySized(keyBytes)
	if err != nil {
		r.unmeasured(property, "residue sweep not run: locked memory is unavailable (%v). Retention by copy "+
			"is unmeasured", err)
		return
	}
	defer release(r, "needle", needle)
	if err := needle.WithBytes(func(b []byte) error {
		_, rerr := io.ReadFull(rand.Reader, b)
		return rerr
	}); err != nil {
		r.fail(property, "generating the needle in locked memory: %v", err)
		return
	}

	// home is the needle's own mapping; a match anywhere else is a copy.
	var home uintptr
	if err := needle.WithBytes(func(b []byte) error {
		var aerr error
		home, aerr = memscan.Addr(b)
		return aerr
	}); err != nil {
		r.fail(property, "locating the needle: %v", err)
		return
	}

	var blob []byte
	if err := needle.WithBytes(func(b []byte) error {
		var perr error
		blob, perr = p.Protect(r.ctx, b)
		return perr
	}); err != nil {
		r.fail(property, "Protect: %v", err)
		return
	}

	// The destination is a second locked mapping, as a real caller's is; while
	// populated it is the control below.
	dst, err := enclave.NewMemorySized(keyBytes)
	if err != nil {
		r.unmeasured(property, "residue sweep not run: a second locked allocation failed (%v). Retention "+
			"by copy is unmeasured", err)
		return
	}
	destroyed := false
	defer func() {
		if !destroyed {
			release(r, "destination", dst)
		}
	}()

	if err := dst.WithBytes(func(d []byte) error {
		return p.Unprotect(r.ctx, blob, d)
	}); err != nil {
		r.fail(property, "Unprotect into a locked destination: %v", err)
		return
	}
	var recovered bool
	if err := needle.WithBytes(func(n []byte) error {
		return dst.WithBytes(func(d []byte) error {
			recovered = equalBytes(n, d)
			return nil
		})
	}); err != nil {
		r.fail(property, "comparing the recovered key: %v", err)
		return
	}
	if !recovered {
		r.fail(property, "Unprotect did not recover the key into the locked destination; the sweep below "+
			"would be measuring nothing")
		return
	}

	// Control: with the key resident in the destination there must be a hit
	// outside home, or a negative result below would be vacuous.
	control, err := sweepOutsideHome(needle, home)
	if err != nil {
		r.unmeasured(property, "residue sweep not run: %v. Retention by copy is unmeasured", err)
		return
	}
	if len(control) == 0 {
		r.unmeasured(property, "residue sweep not run: with the key deliberately resident in a second locked "+
			"mapping the sweep still found no match outside the needle's own mapping, so it cannot see the "+
			"mappings a leak would live in and a negative result would be vacuous. Retention by copy is "+
			"unmeasured")
		return
	}

	if err := dst.WithBytes(func(d []byte) error {
		enclave.Wipe(d)
		return nil
	}); err != nil {
		r.fail(property, "wiping the destination: %v", err)
		return
	}
	// A refused release cannot taint the sweep: the pages were wiped above.
	release(r, "destination", dst)
	destroyed = true

	after, err := sweepOutsideHome(needle, home)
	if err != nil {
		r.unmeasured(property, "residue sweep failed after its control succeeded: %v. Retention by copy is "+
			"unmeasured", err)
		return
	}
	if len(after) > 0 {
		r.fail(property, "the protected key is byte-exact resident in %d mapping(s) outside the caller's "+
			"own — with the caller's destination wiped and unmapped, so every legitimate copy is gone. The "+
			"provider RETAINED a copy of the key, or materialized one and did not wipe it, which the seam "+
			"requires: %q. (Instrument: this same sweep found the material while the destination was alive, "+
			"so it is not blind.)", len(after), after[0])
	}
	r.note("providertest: residue sweep ran — %d mapping(s) held the key while the destination was alive, "+
		"%d after it was wiped and unmapped", len(control), len(after))
}

// sweepProcess is the platform sweep; a variable so a test can blind it.
var sweepProcess = memscan.Find

// sweepOutsideHome returns the mappings, other than the one containing home,
// in which the material held in probe is byte-exact resident.
func sweepOutsideHome(probe enclave.ByteAccess, home uintptr) ([]string, error) {
	var hits []string
	var scanErr error
	if err := probe.WithBytes(func(needle []byte) error {
		hits, scanErr = sweepProcess(needle, home)
		return nil
	}); err != nil {
		return nil, &stepError{step: "borrowing the needle", err: err}
	}
	return hits, scanErr
}

// equalBytes is written out so borrowed slices are never passed to code this
// package does not control. It makes no timing claim.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// release destroys a locked mapping the residue check made for itself. A
// refusal is the environment's doing, not the provider's, so it is noted
// rather than failed.
func release(r *report, what string, e enclave.Handle) {
	if err := e.Destroy(); err != nil {
		r.note("providertest: releasing the residue check's %s was refused: %v", what, err)
	}
}

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
	"fmt"
	"io"

	enclave "github.com/jeremyhahn/go-enclave"
)

// checkNoResidueAfterUnprotect is the corroborating instrument: the only one
// that can see a retained COPY, which the spy by construction cannot.
//
// # Why this is second and not first
//
// The spy decides; this sweep corroborates. Two failure modes, both measured in
// this repository (#45), are the reason that ordering is not a matter of taste:
//
//   - A sweep can PLANT what it looks for. Its scan buffer holds a copy of
//     everything it reads, needle included, and an unwiped buffer becomes heap
//     garbage the next sweep finds and reports as a leak in the code under test.
//     [residueMappings] wipes after every mapping, not merely on return.
//   - A sweep-based residue claim is UNFALSIFIABLE for anything transiting a
//     stack local. A stack growth between filling a local and wiping it strands
//     the pre-wipe bytes on the freed old stack, where no wipe reaches and no
//     amount of care by the provider helps.
//
// So a negative result here is worth something only in the company of the spy,
// and this check refuses to report a negative it has not first proven it could
// turn positive.
//
// # What it measures
//
// [enclave.KeyProtector] requires that a provider whose underlying API returns
// a fresh slice — which is every real backend — "must copy into key and wipe its
// transient". The wipe is the whole of the requirement that the signature
// cannot express, and this is the measurement of it: protect a needle that
// exists ONLY in locked pages, recover it into a second locked mapping, destroy
// that mapping, and then require that the needle appears nowhere in the process
// but its own home.
//
// The needle is generated straight into locked memory and every comparison
// happens inside a borrow, so the suite never creates a heap copy of its own to
// find. A test that plants a bare heap or stack control copy inherits the flake
// described above.
func checkNoResidueAfterUnprotect(r *report, cfg Config) {
	const property = "no copy of the key is findable in the process after Unprotect returns"

	if cfg.SkipResidueSweep != "" {
		r.note("providertest: residue sweep SKIPPED by Config.SkipResidueSweep — %q. "+
			"Retention by COPY is therefore unmeasured for this provider; only retention by reference was "+
			"checked, and the two are different defects", cfg.SkipResidueSweep)
		return
	}
	if !sweepSupported {
		r.note("providertest: residue sweep not run: %s. Retention by copy is unmeasured on this platform; "+
			"run the suite on Linux to measure it", sweepUnsupportedReason)
		return
	}

	p, err := newProtector(cfg)
	if err != nil {
		r.fail(property, "%v", err)
		return
	}

	// The needle exists only here, in locked pages. A []byte literal or a
	// make+rand.Read would put a copy on the heap and the sweep would find the
	// suite's own doing in every run.
	needle, err := enclave.NewMemoryEnclaveSized(keyBytes)
	if err != nil {
		r.note("providertest: residue sweep not run: locked memory is unavailable (%v). Retention by copy "+
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

	// home is the mapping the needle itself lives in. Every legitimate match is
	// inside it; a match anywhere else is a copy that should not exist.
	var home uintptr
	if err := needle.WithBytes(func(b []byte) error {
		var aerr error
		home, aerr = addrOf(b)
		return aerr
	}); err != nil {
		r.fail(property, "locating the needle: %v", err)
		return
	}

	var blob []byte
	if err := needle.WithBytes(func(b []byte) error {
		var perr error
		blob, perr = p.Protect(b)
		return perr
	}); err != nil {
		r.fail(property, "Protect: %v", err)
		return
	}

	// The destination is a second locked mapping, which is both what a real
	// caller hands a provider and — while it is alive and populated — the
	// non-vacuity control below.
	dst, err := enclave.NewMemoryEnclaveSized(keyBytes)
	if err != nil {
		r.note("providertest: residue sweep not run: a second locked allocation failed (%v)", err)
		return
	}
	destroyed := false
	defer func() {
		if !destroyed {
			release(r, "destination", dst)
		}
	}()

	if err := dst.WithBytes(func(d []byte) error {
		return p.Unprotect(blob, d)
	}); err != nil {
		r.fail(property, "Unprotect into a locked destination: %v", err)
		return
	}
	// Compared from inside nested borrows so neither value becomes a heap copy.
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

	// CONTROL FIRST, and a real one: with the plaintext deliberately resident in
	// a second mapping there must be a hit OUTSIDE the needle's home. That
	// proves this sweep can see a second place — which is exactly what a
	// negative result depends on and what the first version of this technique in
	// this repository never established. It skipped kernel-NAMED mappings, and
	// the Go runtime names its heap `[anon: Go: heap]`; measured, that left one
	// mapping swept and thirty skipped, and a provider retaining the plaintext
	// on the heap forever went unnoticed by the one test written to catch it.
	control, err := sweepOutsideHome(needle, home)
	if err != nil {
		r.note("providertest: residue sweep not run: %v. Retention by copy is unmeasured", err)
		return
	}
	if len(control) == 0 {
		r.note("providertest: residue sweep not run: with the key deliberately resident in a second locked " +
			"mapping the sweep still found no match outside the needle's own mapping, so it cannot see the " +
			"mappings a leak would live in and a negative result would be vacuous. Retention by copy is " +
			"unmeasured")
		return
	}

	// The caller is done: it wipes its destination and gives the pages back.
	// From here the needle may exist in exactly one place.
	if err := dst.WithBytes(func(d []byte) error {
		enclave.Wipe(d)
		return nil
	}); err != nil {
		r.fail(property, "wiping the destination: %v", err)
		return
	}
	// A refused release cannot taint the sweep below: the destination was
	// wiped just above, so pages the kernel kept hold no copy of the key.
	release(r, "destination", dst)
	destroyed = true

	after, err := sweepOutsideHome(needle, home)
	if err != nil {
		r.fail(property, "sweeping process memory: %v", err)
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

// sweepOutsideHome returns the mappings, other than the one containing home,
// in which the material held in probe is byte-exact resident. The needle is
// read from inside a borrow so it never exists as a heap value the sweep could
// find and misreport.
func sweepOutsideHome(probe *enclave.MemoryEnclave, home uintptr) ([]string, error) {
	var hits []string
	var scanErr error
	if err := probe.WithBytes(func(needle []byte) error {
		hits, scanErr = residueMappings(needle, home)
		return nil
	}); err != nil {
		return nil, &stepError{step: "borrowing the needle", err: err}
	}
	return hits, scanErr
}

// equalBytes is a plain length-and-content comparison. It is written out rather
// than taken from bytes.Equal only so the borrowed slices are never passed to a
// function whose implementation this package does not control; there is no
// timing claim here, because both sides are the suite's own values.
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

// addrOf returns the address of a slice's first element. It goes through the
// fmt verb rather than unsafe so that a package asserting a memory property
// does not itself need the unsafe package.
func addrOf(b []byte) (uintptr, error) {
	if len(b) == 0 {
		return 0, errEmptySlice
	}
	var addr uint64
	if _, err := fmt.Sscanf(fmt.Sprintf("%p", b), "0x%x", &addr); err != nil {
		return 0, &stepError{step: "providertest: parsing slice address", err: err}
	}
	return uintptr(addr), nil
}

// release destroys a locked mapping the residue check made for itself. A
// refused release is the environment's doing rather than the provider's, so it
// is noted rather than failed: the pages stay on go-enclave's shutdown ledger,
// and nothing the check measures depends on them being gone.
func release(r *report, what string, e *enclave.MemoryEnclave) {
	if err := e.Destroy(); err != nil {
		r.note("providertest: releasing the residue check's %s was refused: %v", what, err)
	}
}

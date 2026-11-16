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
	"errors"
	"slices"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/internal/memscan"
)

// plantedSweep returns a sweep that reports hit for the whole key and fails
// every half-key probe with errProbe, as a mapping that turns unreadable
// between probes would.
func plantedSweep(hit string, errProbe error) func([]byte, uintptr) (memscan.Result, error) {
	return func(p []byte, _ uintptr) (memscan.Result, error) {
		if len(p) == keyBytes {
			return memscan.Result{Hits: []string{hit}}, nil
		}
		return memscan.Result{}, errProbe
	}
}

// TestSweepForKeyOrHalfKeepsAHitAcrossALaterProbeError pins that a hit one
// probe made survives a later probe's error, and that probes with no hit and
// an error still fail closed.
func TestSweepForKeyOrHalfKeepsAHitAcrossALaterProbeError(t *testing.T) {
	errProbe := errors.New("planted: a mapping turned unreadable")
	orig := sweepProcess
	t.Cleanup(func() { sweepProcess = orig })

	sweepProcess = plantedSweep("planted-mapping", errProbe)
	res, err := sweepForKeyOrHalf(make([]byte, keyBytes), 0)
	if err != nil || !slices.Equal(res.Hits, []string{"planted-mapping"}) {
		t.Fatalf("sweepForKeyOrHalf = %q, %v; want the full-key hit and no error", res.Hits, err)
	}

	sweepProcess = func([]byte, uintptr) (memscan.Result, error) { return memscan.Result{}, errProbe }
	if res, err := sweepForKeyOrHalf(make([]byte, keyBytes), 0); !errors.Is(err, errProbe) || res.Hits != nil {
		t.Fatalf("sweepForKeyOrHalf with every probe failing = %q, %v; want no hits and the probe error", res.Hits, err)
	}
}

// TestSweepForKeyOrHalfKeepsTheGuardPageCount pins that the half-key probes
// carry the sweep's skipped guard-page count through, so the residue note
// still reports it.
func TestSweepForKeyOrHalfKeepsTheGuardPageCount(t *testing.T) {
	orig := sweepProcess
	t.Cleanup(func() { sweepProcess = orig })
	sweepProcess = func(p []byte, _ uintptr) (memscan.Result, error) {
		return memscan.Result{GuardPages: len(p)}, nil
	}
	res, err := sweepForKeyOrHalf(make([]byte, keyBytes), 0)
	if err != nil || res.GuardPages != keyBytes || res.Hits != nil {
		t.Fatalf("sweepForKeyOrHalf = %+v, %v; want no hits and %d guard pages", res, err, keyBytes)
	}
}

// TestAResidueHitBeforeAProbeErrorIsAFinding pins that a key the sweep found
// is charged to the provider as a PropertyError even when a later probe in
// the same sweep errored, not reported as a host that could not measure.
func TestAResidueHitBeforeAProbeErrorIsAFinding(t *testing.T) {
	const property = "no copy of the key is findable in the process after Unprotect returns"
	orig := sweepProcess
	t.Cleanup(func() { sweepProcess = orig })
	sweepProcess = plantedSweep("planted-mapping", errors.New("planted: /proc/self/mem unreadable"))

	cfg := Config{
		New:   func() (any, error) { return software(), nil },
		Modes: []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation},
		Logf:  t.Logf,
	}
	err := TestProvider(t.Context(), cfg)
	var pe *PropertyError
	if !errors.As(err, &pe) || pe.Property != property {
		t.Fatalf("TestProvider = %v, want a *PropertyError for %q", err, property)
	}
}

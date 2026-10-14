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
	"context"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Covers detection.go: Detect on the devcontainer's plain host, a host with no
// TEE or secure element, through the public package. No test in this binary
// registers a usable backend ranked above locked memory, so every Detect here
// must select the default.

// absentProber is a backend whose device this host lacks.
type absentProber struct{ name string }

// errAbsentDevice is absentProber's own probe failure.
var errAbsentDevice = errors.New("absent: no such device")

func (p *absentProber) Name() string                { return p.name }
func (p *absentProber) Rank() int                   { return 100 }
func (p *absentProber) Probe(context.Context) error { return errAbsentDevice }

// resultOf returns Detect's result for name, failing the test without one.
func resultOf(t *testing.T, results []enclave.ProbeResult, name string) enclave.ProbeResult {
	t.Helper()
	for _, r := range results {
		if r.Backend == name {
			return r
		}
	}
	t.Fatalf("Detect has no result for %q", name)
	return enclave.ProbeResult{}
}

// TestBackendDetection_SelectsLockedMemoryOnAPlainHost is the release
// criterion: on a plain host detection selects the memory backend, and the
// backend it selects makes a working enclave.
func TestBackendDetection_SelectsLockedMemoryOnAPlainHost(t *testing.T) {
	selected, results := enclave.Detect(t.Context())
	if selected != enclave.DefaultBackend() || selected.Name() != enclave.LockedMemoryBackendName {
		t.Fatalf("Detect selected %q, want %q", selected.Name(), enclave.LockedMemoryBackendName)
	}
	if r := resultOf(t, results, enclave.LockedMemoryBackendName); r.Rank != 0 || r.Err != nil {
		t.Fatalf("locked-memory result = %+v, want rank 0, usable", r)
	}

	e, err := enclave.NewMemory([]byte("detected"))
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	t.Cleanup(func() { _ = e.Destroy() })
	if e.Backend() != selected {
		t.Fatalf("an enclave reports backend %q, not the one Detect selected", e.Backend().Name())
	}
}

// TestBackendDetection_ReportsWhyItPassedABackendOver registers a higher-ranked
// backend whose device is absent and a backend that cannot be probed, and
// requires Detect to fall back to locked memory and say why for each.
func TestBackendDetection_ReportsWhyItPassedABackendOver(t *testing.T) {
	absent := &absentProber{name: uniqueBackendName("detect-absent")}
	plain := &fakeBackend{name: uniqueBackendName("detect-plain")}
	for _, b := range []enclave.Backend{absent, plain} {
		if err := enclave.Register(b); err != nil {
			t.Fatalf("Register(%q) = %v", b.Name(), err)
		}
	}

	selected, results := enclave.Detect(t.Context())
	if selected != enclave.DefaultBackend() {
		t.Fatalf("Detect selected %q, want the default", selected.Name())
	}

	r := resultOf(t, results, absent.name)
	var pe *enclave.ProbeError
	if r.Rank != 100 || !errors.Is(r.Err, enclave.ErrBackendUnavailable) || !errors.Is(r.Err, errAbsentDevice) ||
		!errors.As(r.Err, &pe) || pe.Backend != absent.name {
		t.Fatalf("absent result = %+v, want rank 100 and a ProbeError carrying the device error", r)
	}

	r = resultOf(t, results, plain.name)
	var ce *enclave.CapabilityError
	if !errors.As(r.Err, &ce) || ce.Capability != enclave.CapabilityProbe {
		t.Fatalf("plain result = %+v, want a CapabilityError for %q", r, enclave.CapabilityProbe)
	}
}

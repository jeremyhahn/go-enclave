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
	"bytes"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// newSecretMemory builds the secretmem backend over a fresh Allocator.
func newSecretMemory() (enclave.Backend, error) {
	a, err := enclave.NewAllocator(1 << 20)
	if err != nil {
		return nil, err
	}
	return enclave.NewSecretMemory(a)
}

// requireSecretMemory returns the secretmem backend, or skips naming why this
// host cannot run it. It runs in the parent process: a skip inside an isolated
// child fails the parent.
func requireSecretMemory(t *testing.T) enclave.Backend {
	t.Helper()
	b, err := newSecretMemory()
	if errors.Is(err, enclave.ErrMemfdSecretUnavailable) {
		t.Skipf("this platform has no memfd_secret: %v", err)
	}
	if err != nil {
		t.Fatalf("NewSecretMemory: %v", err)
	}
	if err := b.(enclave.Prober).Probe(t.Context()); err != nil {
		if !errors.Is(err, enclave.ErrMemfdSecretUnavailable) {
			t.Fatalf("Probe = %v, want a refusal matching ErrMemfdSecretUnavailable", err)
		}
		t.Skipf("the host refuses memfd_secret: %v", err)
	}
	return b
}

func TestLinuxSecretmem_PassesBackendConformance(t *testing.T) {
	requireSecretMemory(t)
	cfg := backendtest.Config{
		New:                 newSecretMemory,
		BackendCapabilities: []enclave.Capability{enclave.CapabilityImport, enclave.CapabilityProbe},
		Handles: []backendtest.HandleCase{{
			Name:         "material",
			Import:       []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)},
			ImportSize:   32,
			Capabilities: []enclave.Capability{enclave.CapabilityBytes, enclave.CapabilityFreeze},
		}},
		Logf: t.Logf,
		// The sweep reads the process through /proc/self/mem, which the
		// kernel refuses for secretmem pages: the property this backend adds.
		SkipResidueSweep: "memfd_secret pages are unreadable through /proc/self/mem",
	}
	if err := backendtest.TestBackend(t.Context(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxSecretmem_DetectSelectsItAboveLockedMemory(t *testing.T) {
	requireSecretMemory(t)
	// Registration is for the life of the process, so it happens in a child.
	isolated(t, childOpts{}, func(t *testing.T) {
		b, err := newSecretMemory()
		if err != nil {
			t.Fatalf("NewSecretMemory: %v", err)
		}
		if err := enclave.Register(b); err != nil {
			t.Fatalf("Register: %v", err)
		}
		selected, results := enclave.Detect(t.Context())
		if selected != b {
			t.Fatalf("Detect selected %q, want %q", selected.Name(), enclave.SecretMemoryBackendName)
		}
		if r := resultOf(t, results, enclave.SecretMemoryBackendName); r.Rank != 1 || r.Err != nil {
			t.Fatalf("secretmem result = %+v, want rank 1, usable", r)
		}
		if r := resultOf(t, results, enclave.LockedMemoryBackendName); r.Rank != 0 || r.Err != nil {
			t.Fatalf("locked-memory result = %+v, want rank 0, usable (outranked)", r)
		}

		want := []byte("selected by detection")
		h, err := selected.(enclave.Importer).Import(t.Context(), bytes.Clone(want), enclave.WithPurpose(enclave.PurposeMaterial))
		if err != nil {
			t.Fatalf("Import: %v", err)
		}
		t.Cleanup(func() { _ = h.Destroy() })
		if h.Backend() != b {
			t.Fatalf("the handle reports backend %q, not the one Detect selected", h.Backend().Name())
		}
		if eq, err := h.(enclave.ByteAccess).EqualTo(want); err != nil || !eq {
			t.Fatalf("EqualTo = %t, %v; want the imported material", eq, err)
		}
	})
}

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
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// Covers backendtest: the shipped locked-memory backend (an Allocator) run
// through the conformance suite a backend author is told to use, inside the
// devcontainer, where its residue sweep can run.

func allocatorBackendConfig(t *testing.T) backendtest.Config {
	return backendtest.Config{
		New: func() (enclave.Backend, error) {
			return enclave.NewAllocator(1 << 20)
		},
		BackendCapabilities: []enclave.Capability{enclave.CapabilityImport},
		Handles: []backendtest.HandleCase{{
			Name:       "material",
			Import:     []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)},
			ImportSize: 32,
			Capabilities: []enclave.Capability{
				enclave.CapabilityBytes,
				enclave.CapabilityFreeze,
			},
		}},
		Logf: t.Logf,
	}
}

func TestBackendConformance_AllocatorPasses(t *testing.T) {
	if err := backendtest.TestBackend(context.Background(), allocatorBackendConfig(t)); err != nil {
		t.Fatalf("the locked-memory backend fails conformance: %v", err)
	}
}

func TestBackendConformance_AnUnderClaimedBackendIsAFinding(t *testing.T) {
	cfg := allocatorBackendConfig(t)
	cfg.BackendCapabilities = nil
	err := backendtest.TestBackend(context.Background(), cfg)
	var pe *backendtest.PropertyError
	if err == nil || !errors.As(err, &pe) {
		t.Fatalf("conformance with an under-claimed capability list: err = %v, want a PropertyError", err)
	}
}

func TestBackendConformance_AnInvalidConfigIsRefused(t *testing.T) {
	err := backendtest.TestBackend(context.Background(), backendtest.Config{})
	if !errors.Is(err, backendtest.ErrInvalidConfig) {
		t.Fatalf("empty Config: err = %v, want ErrInvalidConfig", err)
	}
}

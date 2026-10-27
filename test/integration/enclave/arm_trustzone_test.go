// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration && optee

package enclave_test

import (
	"context"
	"errors"
	"os"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// Covers backendtest against the arm-trustzone backend on OP-TEE (#250). The
// optee tag keeps it out of every other run; `make
// integration-test-arm-trustzone` runs it against trusted-firmware's QEMU
// fixture. The backend is out of tree (#206): the harness finds it in the
// registry by name and never imports it, so go-enclave keeps golang.org/x/sys
// as its only dependency. The registry is per process, so the fixture cannot
// fill it: an optee-tagged file in this package, arm_trustzone_register_test.go,
// registers the backend in-process with enclave.Register and sets
// armTrustZoneRegistered from its init. #206 supplies that file; until then
// the harness refuses with a *backendtest.RegistrationError, and `make
// integration-test-arm-trustzone` refuses before it builds.

// armTrustZoneRegistered is set by the init of arm_trustzone_register_test.go
// once that file registers the backend in this process.
var armTrustZoneRegistered bool

const (
	// armTrustZoneBackend is the name the fixture registers the backend under.
	armTrustZoneBackend = "arm-trustzone"
	// opteeEndpointVar names the TEE client endpoint the fixture sets, such as
	// the guest's /dev/tee0; the harness never assumes a path.
	opteeEndpointVar = "GO_ENCLAVE_OPTEE_ENDPOINT"
	// opteeRandomSize is the size of the handle the TA's rng command fills.
	opteeRandomSize = 32
)

// teeConnector is what the harness asks of the registered backend beyond the
// seam: a fresh backend bound to the TEE at endpoint, one per check.
type teeConnector interface {
	Connect(endpoint string) (enclave.Backend, error)
}

// teeRandom is how a connected backend makes a handle: n bytes from the TA's
// rng command (0x2), held in locked memory.
type teeRandom interface {
	Random(ctx context.Context, n int) (enclave.Handle, error)
}

// armTrustZoneConfig is the conformance run for the TA's command set, version
// (0x1) behind Probe and rng (0x2) behind the one handle case. It fails with a
// typed error, never a skip, when the endpoint is unset, when registered
// reports that no file in the binary registers the backend, or when no backend
// is registered under the name: a skipped conformance run would read as a pass.
func armTrustZoneConfig(t *testing.T, registered bool) (backendtest.Config, error) {
	endpoint := os.Getenv(opteeEndpointVar)
	if endpoint == "" {
		return backendtest.Config{}, &backendtest.EndpointError{Variable: opteeEndpointVar}
	}
	if !registered {
		return backendtest.Config{}, &backendtest.RegistrationError{Backend: armTrustZoneBackend}
	}
	backend, err := enclave.Lookup(armTrustZoneBackend)
	if err != nil {
		return backendtest.Config{}, err
	}
	var connector teeConnector
	if !enclave.As(backend, &connector) {
		return backendtest.Config{}, &enclave.CapabilityError{Backend: armTrustZoneBackend, Capability: enclave.CapabilityProbe}
	}
	return backendtest.Config{
		New:                 func() (enclave.Backend, error) { return connector.Connect(endpoint) },
		BackendCapabilities: []enclave.Capability{enclave.CapabilityProbe},
		Handles: []backendtest.HandleCase{{
			Name: "rng",
			New: func(ctx context.Context, b enclave.Backend) (enclave.Handle, error) {
				var r teeRandom
				if !enclave.As(b, &r) {
					return nil, &enclave.CapabilityError{Backend: armTrustZoneBackend, Capability: enclave.CapabilityBytes}
				}
				return r.Random(ctx, opteeRandomSize)
			},
			Capabilities: []enclave.Capability{enclave.CapabilityBytes},
		}},
		Logf: t.Logf,
	}, nil
}

func TestBackendConformance_ArmTrustZoneOnOPTEE(t *testing.T) {
	cfg, err := armTrustZoneConfig(t, armTrustZoneRegistered)
	if err != nil {
		t.Fatalf("the arm-trustzone harness cannot run: %v", err)
	}
	if err := backendtest.TestBackend(context.Background(), cfg); err != nil {
		t.Fatalf("the arm-trustzone backend fails conformance: %v", err)
	}
}

func TestBackendConformance_ArmTrustZoneRefusesWithoutAnEndpoint(t *testing.T) {
	t.Setenv(opteeEndpointVar, "")
	_, err := armTrustZoneConfig(t, true)
	var unset *backendtest.EndpointError
	if !errors.Is(err, backendtest.ErrNoEndpoint) || !errors.As(err, &unset) || unset.Variable != opteeEndpointVar {
		t.Fatalf("armTrustZoneConfig with $%s empty = %v, want a *backendtest.EndpointError naming it", opteeEndpointVar, err)
	}
}

func TestBackendConformance_ArmTrustZoneRefusesWithoutARegistration(t *testing.T) {
	t.Setenv(opteeEndpointVar, "/dev/tee0")
	_, err := armTrustZoneConfig(t, false)
	var missing *backendtest.RegistrationError
	if !errors.Is(err, backendtest.ErrNoRegistration) || !errors.As(err, &missing) || missing.Backend != armTrustZoneBackend {
		t.Fatalf("armTrustZoneConfig without a registration = %v, want a *backendtest.RegistrationError naming %s", err, armTrustZoneBackend)
	}
}

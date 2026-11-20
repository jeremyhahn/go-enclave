package amdsev_test

import (
	"errors"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// This file is the one seam to the amd-sev backend module. Until this module
// requires it, newBackend fails with errBackendNotLinked, so every test that
// needs the backend fails, never skips. Linking it is the one-line change:
// require the module and make newBackend return its constructor's result.

// errBackendNotLinked is newBackend's error until the backend is required.
var errBackendNotLinked = errors.New("amdsev: the amd-sev backend module is not required by backends/amdsev/integration yet; require it and return its constructor from newBackend")

// newBackend constructs the amd-sev backend: inside an SEV-SNP guest a
// backend whose ConfinesProcess is true, elsewhere an error that is
// enclave.ErrBackendUnavailable.
func newBackend() (enclave.Backend, error) {
	return nil, errBackendNotLinked
}

// conformance is backendtest's configuration for the amd-sev backend: the
// whole guest is the confined process, and key material imports into it.
func conformance(logf func(string, ...any)) backendtest.Config {
	return backendtest.Config{
		New:                 newBackend,
		BackendCapabilities: []enclave.Capability{enclave.CapabilityConfine, enclave.CapabilityImport},
		Handles: []backendtest.HandleCase{{
			Name:         "material",
			Import:       []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)},
			ImportSize:   32,
			Capabilities: []enclave.Capability{enclave.CapabilityBytes, enclave.CapabilityFreeze},
		}},
		Logf: logf,
	}
}

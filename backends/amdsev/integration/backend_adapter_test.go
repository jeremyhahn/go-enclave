package amdsev_test

import (
	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backends/amdsev"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// allocatorSize is the locked arena newBackend gives the backend: room for the
// conformance suite's handles.
const allocatorSize = 1 << 20

// newBackend constructs the amd-sev backend with amdsev.New over a fresh
// allocator: inside an SEV-SNP guest a backend whose ConfinesProcess is true,
// elsewhere no backend and an error that is amdsev.ErrSNPGuestUnavailable.
func newBackend() (enclave.Backend, error) {
	a, err := enclave.NewAllocator(allocatorSize)
	if err != nil {
		return nil, err
	}
	return amdsev.New(a)
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

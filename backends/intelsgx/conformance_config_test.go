package intelsgx

import (
	"context"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// conformanceConfig is the backendtest configuration the hardware
// conformance test runs (conformance_sgx_test.go), with verify as its
// relying party.
func conformanceConfig(verify func([]byte, enclave.Evidence) error, logf func(string, ...any)) backendtest.Config {
	material := []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)}
	return backendtest.Config{
		New: func() (enclave.Backend, error) { return New(context.Background()) },
		BackendCapabilities: []enclave.Capability{
			enclave.CapabilityImport, enclave.CapabilitySweep, enclave.CapabilityConfine,
			enclave.CapabilityAttest, enclave.CapabilityProbe,
		},
		Handles: []backendtest.HandleCase{{
			Name:         "material",
			Import:       material,
			ImportSize:   32,
			Capabilities: []enclave.Capability{enclave.CapabilityBytes, enclave.CapabilityFreeze},
		}},
		VerifyEvidence: verify,
		Logf:           logf,
	}
}

// TestConformanceConfig_PassesBackendtestValidation runs the hardware
// conformance configuration through backendtest without SGX: the backend
// constructor is a stand-in that fails, so the run stops after the suite
// has validated the configuration, and the error is never a configuration
// refusal.
func TestConformanceConfig_PassesBackendtestValidation(t *testing.T) {
	errNoHardware := errors.New("stand-in: no SGX enclave")
	cfg := conformanceConfig(func([]byte, enclave.Evidence) error { return errQuoteNotVerifiedStandIn }, t.Logf)
	cfg.New = func() (enclave.Backend, error) { return nil, errNoHardware }
	err := backendtest.TestBackend(context.Background(), cfg)
	if errors.Is(err, backendtest.ErrInvalidConfig) || errors.Is(err, backendtest.ErrUncheckedCapability) {
		t.Fatalf("backendtest refuses the intel-sgx conformance config: %v", err)
	}
	if err == nil {
		t.Fatal("backendtest passed a backend whose constructor fails")
	}
}

var errQuoteNotVerifiedStandIn = errors.New("stand-in: no quote verifier")

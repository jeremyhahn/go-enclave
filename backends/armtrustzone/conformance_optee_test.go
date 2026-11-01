//go:build optee

package armtrustzone

import (
	"context"
	"os"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// opteeEndpointVar names the TEE device, as the arm-trustzone harness sets
// it in the guest: /dev/tee0.
const opteeEndpointVar = "GO_ENCLAVE_OPTEE_ENDPOINT"

// TestBackendConformance_OnOPTEE registers the backend in-process and runs
// backendtest against the trusted application on OP-TEE, with the TA's
// capabilities: the GET_INFO probe and random-filled handles. It is the
// optee-tagged binary the harness drops into the guest.
func TestBackendConformance_OnOPTEE(t *testing.T) {
	endpoint := os.Getenv(opteeEndpointVar)
	if endpoint == "" {
		t.Fatalf("the arm-trustzone conformance test cannot run: %v", &backendtest.EndpointError{Variable: opteeEndpointVar})
	}
	if err := enclave.Register(Connector{}); err != nil {
		t.Fatalf("enclave.Register: %v", err)
	}
	registered, err := enclave.Lookup(Name)
	if err != nil {
		t.Fatalf("enclave.Lookup(%q): %v", Name, err)
	}
	var connector interface {
		Connect(endpoint string) (enclave.Backend, error)
	}
	if !enclave.As(registered, &connector) {
		t.Fatalf("the registered %q backend has no Connect", Name)
	}
	cfg := backendtest.Config{
		New: func() (enclave.Backend, error) {
			b, err := connector.Connect(endpoint)
			if err == nil {
				t.Cleanup(func() { _ = b.(*Backend).Close() })
			}
			return b, err
		},
		BackendCapabilities: []enclave.Capability{enclave.CapabilityProbe},
		Handles: []backendtest.HandleCase{{
			Name: "rng",
			New: func(ctx context.Context, b enclave.Backend) (enclave.Handle, error) {
				return b.(*Backend).Random(ctx, 32)
			},
			Capabilities: []enclave.Capability{enclave.CapabilityBytes},
		}},
		Logf: t.Logf,
	}
	if err := backendtest.TestBackend(context.Background(), cfg); err != nil {
		t.Fatalf("the arm-trustzone backend fails conformance: %v", err)
	}
}

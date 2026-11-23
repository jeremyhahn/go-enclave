//go:build sgx && linux && amd64

package intelsgx

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-enclave/backendtest"
)

// The tests in this file run on the real part only: the module's test binary
// inside a non-debug Gramine SGX enclave that can quote, as the design's test
// plan sets out (docs/backends/intel-sgx.md). There is no simulator path and no
// skip: outside such an enclave construction fails and so does the test.

func newEnclaveBackend(t *testing.T) *Backend {
	t.Helper()
	b, err := New(context.Background())
	if err != nil {
		t.Fatalf("the intel-sgx conformance test cannot run outside a non-debug SGX enclave: %v", err)
	}
	return b
}

func TestBackendConformance_InSGXEnclave(t *testing.T) {
	newEnclaveBackend(t)
	if err := backendtest.TestBackend(context.Background(), conformanceConfig(t.Logf)); err != nil {
		t.Fatalf("the intel-sgx backend fails conformance: %v", err)
	}
}

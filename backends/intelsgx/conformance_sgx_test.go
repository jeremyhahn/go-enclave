//go:build sgx && linux && amd64

package intelsgx

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"sync"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// The tests in this file run on the real part only: the module's test binary
// inside a non-debug Gramine SGX enclave that can quote, as the design's test
// plan sets out (docs/backends/intel-sgx.md). There is no simulator path and no
// skip: outside such an enclave construction fails and so does the test.

// newQuoteVerifier is the relying party the hardware runner supplies (see
// quoteVerifierFromEnv): without it the test fails, since a header and nonce
// check alone would pass an unsigned quote.
func newQuoteVerifier(t *testing.T) *quoteVerifier {
	t.Helper()
	v, err := quoteVerifierFromEnv(os.Getenv)
	if err != nil {
		t.Fatalf("the intel-sgx conformance test needs the hardware runner's quote verifier: %v", err)
	}
	return v
}

func newEnclaveBackend(t *testing.T) *Backend {
	t.Helper()
	b, err := New(context.Background())
	if err != nil {
		t.Fatalf("the intel-sgx conformance test cannot run outside a non-debug SGX enclave: %v", err)
	}
	return b
}

func TestBackendConformance_InSGXEnclave(t *testing.T) {
	v := newQuoteVerifier(t)
	newEnclaveBackend(t)
	cfg := conformanceConfig(v.verify, t.Logf)
	if err := backendtest.TestBackend(context.Background(), cfg); err != nil {
		t.Fatalf("the intel-sgx backend fails conformance: %v", err)
	}
}

func TestAttestConcurrentInSGXEnclave(t *testing.T) {
	v := newQuoteVerifier(t)
	b := newEnclaveBackend(t)
	nonces := make([][]byte, 8)
	evs := make([]enclave.Evidence, len(nonces))
	errs := make([]error, len(nonces))
	var wg sync.WaitGroup
	for i := range nonces {
		nonces[i] = make([]byte, 32)
		if _, err := rand.Read(nonces[i]); err != nil {
			t.Fatal(err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			evs[i], errs[i] = b.Attest(context.Background(), nonces[i])
		}()
	}
	wg.Wait()
	for i := range nonces {
		if errs[i] != nil {
			t.Fatalf("Attest(nonce %d) = %v", i, errs[i])
		}
		if err := v.verify(nonces[i], evs[i]); err != nil {
			t.Fatalf("the quote for nonce %d does not verify against it: %v", i, err)
		}
		other := nonces[(i+1)%len(nonces)]
		if err := v.verify(other, evs[i]); !errors.Is(err, ErrReportDataMismatch) {
			t.Fatalf("the quote for nonce %d verifies against another nonce: %v", i, err)
		}
	}
}

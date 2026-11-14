//go:build sgx && linux && amd64

package intelsgx

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// The tests in this file run on the real part only: the module's test binary
// inside a non-debug Gramine SGX enclave that can quote, as the design's test
// plan sets out (docs/backends/intel-sgx.md). There is no simulator path and no
// skip: outside such an enclave construction fails and so does the test.

// verifyQuoteBinding is the relying party's check this module can make on its
// own: the evidence is a version 3 ECDSA quote whose REPORT_DATA is the padded
// nonce and whose enclave is not a debug enclave. The PCK chain, quote
// signature and TCB status are the DCAP verifier's, which the hardware runner
// supplies.
func verifyQuoteBinding(nonce []byte, ev enclave.Evidence) error {
	if ev.Format != EvidenceFormat {
		return fmt.Errorf("evidence format %q, want %q", ev.Format, EvidenceFormat)
	}
	rd, err := padNonce(nonce)
	if err != nil {
		return err
	}
	if err := checkQuote(ev.Data, rd); err != nil {
		return err
	}
	if binary.LittleEndian.Uint64(ev.Data[quoteHeaderSize+attributesOffset:])&flagDebug != 0 {
		return ErrDebugEnclave
	}
	return nil
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
	newEnclaveBackend(t)
	material := []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)}
	cfg := backendtest.Config{
		New: func() (enclave.Backend, error) { return New(context.Background()) },
		BackendCapabilities: []enclave.Capability{
			enclave.CapabilityImport, enclave.CapabilitySweep, enclave.CapabilityConfine,
			enclave.CapabilityAttest, enclave.CapabilityProbe,
		},
		Handles: []backendtest.HandleCase{{
			Name: "material",
			New: func(ctx context.Context, b enclave.Backend) (enclave.Handle, error) {
				key := make([]byte, 32)
				if _, err := rand.Read(key); err != nil {
					return nil, err
				}
				return b.(*Backend).Import(ctx, key, material...)
			},
			Import:       material,
			ImportSize:   32,
			Capabilities: []enclave.Capability{enclave.CapabilityBytes, enclave.CapabilityFreeze},
		}},
		VerifyEvidence: verifyQuoteBinding,
		Logf:           t.Logf,
	}
	if err := backendtest.TestBackend(context.Background(), cfg); err != nil {
		t.Fatalf("the intel-sgx backend fails conformance: %v", err)
	}
}

func TestAttestConcurrentInSGXEnclave(t *testing.T) {
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
		if err := verifyQuoteBinding(nonces[i], evs[i]); err != nil {
			t.Fatalf("the quote for nonce %d does not verify against it: %v", i, err)
		}
		other := nonces[(i+1)%len(nonces)]
		if err := verifyQuoteBinding(other, evs[i]); !errors.Is(err, ErrReportDataMismatch) {
			t.Fatalf("the quote for nonce %d verifies against another nonce: %v", i, err)
		}
	}
}

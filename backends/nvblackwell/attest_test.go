package nvblackwell

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// attestInner counts the calls that reach inner's Attest.
type attestInner struct {
	*testInner
	calls int
}

func (a *attestInner) Attest(context.Context, []byte) (enclave.Evidence, error) {
	a.calls++
	return enclave.Evidence{Format: "tdx-quote", Data: []byte("c")}, nil
}

func attestBackend() (*Backend, *attestInner) {
	in := &attestInner{testInner: &testInner{}}
	return &Backend{inner: in, rank: in.Rank() + 1}, in
}

func TestGPUNonceIsSHA256(t *testing.T) {
	got := gpuNonce([]byte("abc"))
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if hex.EncodeToString(got[:]) != want {
		t.Fatalf("gpuNonce = %x, want %s", got, want)
	}
}

func TestAttestRefusesNonceOutOfBounds(t *testing.T) {
	b, in := attestBackend()
	for _, n := range [][]byte{nil, {}, make([]byte, maxNonce+1)} {
		if _, err := b.Attest(context.Background(), n); !errors.Is(err, enclave.ErrInvalidNonce) {
			t.Errorf("Attest(%d bytes) error = %v, want ErrInvalidNonce", len(n), err)
		}
	}
	if in.calls != 0 {
		t.Fatalf("inner Attest ran %d times for a refused nonce", in.calls)
	}
}

func TestAttestChecksCtx(t *testing.T) {
	b, in := attestBackend()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := b.Attest(ctx, []byte("n")); !errors.Is(err, context.Canceled) {
		t.Fatalf("Attest error = %v, want context.Canceled", err)
	}
	if in.calls != 0 {
		t.Fatal("inner Attest ran under a canceled ctx")
	}
}

// TestAttestReturnsProbesRefusal runs on a host without the driver or a
// Blackwell GPU: Attest returns Probe's typed refusal and never asks inner.
func TestAttestReturnsProbesRefusal(t *testing.T) {
	b, in := attestBackend()
	want := Probe(context.Background())
	if want == nil {
		t.Skip("this host passes Probe; the conformance harness covers Attest here")
	}
	_, err := b.Attest(context.Background(), []byte("n"))
	if err == nil || err.Error() != want.Error() {
		t.Fatalf("Attest error = %v, want Probe's %v", err, want)
	}
	if in.calls != 0 {
		t.Fatal("inner Attest ran on a host Probe refuses")
	}
}

func TestEncodeEvidence(t *testing.T) {
	cpu := enclave.Evidence{Format: "tdx-quote", Data: []byte("c")}
	got, err := encodeEvidence(cpu, []gpuEvidence{
		{Report: []byte("r"), CertChain: []byte("k"), AttestationCertChain: []byte("a")},
		{Report: []byte("r"), CECReport: []byte("e"), CertChain: []byte("k"), AttestationCertChain: []byte("a")},
	})
	if err != nil {
		t.Fatalf("encodeEvidence: %v", err)
	}
	const chains = `"attestation-cert-chain":["application/pem-certificate-chain","YQ"],` +
		`"cert-chain":["application/pem-certificate-chain","aw"]`
	const report = `"report":["application/vnd.go-enclave.nvidia-gpu-report","cg",4]`
	want := `{"cpu":["application/vnd.go-enclave.tdx-quote","Yw",4],` +
		`"gpu0":{` + chains + `,` + report + `},` +
		`"gpu1":{"attestation-cert-chain":["application/pem-certificate-chain","YQ"],` +
		`"cec-report":["application/vnd.go-enclave.nvidia-cec-report","ZQ",4],` +
		`"cert-chain":["application/pem-certificate-chain","aw"],` + report + `}}`
	if string(got) != want {
		t.Fatalf("encodeEvidence =\n%s\nwant\n%s", got, want)
	}
}

func TestEncodeEvidenceRefuses(t *testing.T) {
	gpu := gpuEvidence{Report: []byte("r"), CertChain: []byte("k"), AttestationCertChain: []byte("a")}
	cpu := enclave.Evidence{Format: "tdx-quote", Data: []byte("c")}
	if _, err := encodeEvidence(cpu, nil); !errors.Is(err, errMalformedCMW) {
		t.Errorf("no GPUs: error = %v, want errMalformedCMW", err)
	}
	for _, f := range []string{"", "TDX", "tdx quote", "a/b"} {
		bad := enclave.Evidence{Format: f, Data: []byte("c")}
		if _, err := encodeEvidence(bad, []gpuEvidence{gpu}); !errors.Is(err, errMalformedCMW) {
			t.Errorf("format %q: error = %v, want errMalformedCMW", f, err)
		}
	}
	if _, err := encodeEvidence(cpu, []gpuEvidence{{CertChain: []byte("k"), AttestationCertChain: []byte("a")}}); !errors.Is(err, errMalformedCMW) {
		t.Errorf("empty report: error = %v, want errMalformedCMW", err)
	}
}

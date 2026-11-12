package macse

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// This host has no Secure Enclave binding, so the probe refuses for real at
// its first step, with the typed unavailable error naming it.
func TestProbe_RefusesWithoutTheBinding(t *testing.T) {
	err := probe(context.Background())
	if !errors.Is(err, ErrSecureEnclaveUnavailable) {
		t.Fatalf("probe = %v, want ErrSecureEnclaveUnavailable", err)
	}
	if errors.Is(err, ErrSecureEnclaveOperation) {
		t.Fatalf("probe = %v, matches ErrSecureEnclaveOperation", err)
	}
	var pe *PlatformError
	if !errors.As(err, &pe) {
		t.Fatalf("probe = %T, want *PlatformError", err)
	}
	if pe.Op != OpCreate || pe.GOOS != runtime.GOOS || pe.GOARCH != runtime.GOARCH {
		t.Fatalf("PlatformError = %+v, want Op %q on %s/%s", pe, OpCreate, runtime.GOOS, runtime.GOARCH)
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("PlatformError has a cause: %v", errors.Unwrap(err))
	}
	if !strings.Contains(err.Error(), OpCreate) {
		t.Fatalf("Error() = %q, does not name the step", err)
	}
}

func TestProbe_Context(t *testing.T) {
	//nolint:staticcheck // SA1012: the seam says a nil ctx never ends
	if err := probe(nil); !errors.Is(err, ErrSecureEnclaveUnavailable) {
		t.Fatalf("probe(nil) = %v, want ErrSecureEnclaveUnavailable", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("probe(cancelled) = %v, want context.Canceled", err)
	}
}

// probeVector is a software P-256 key's public point, a digest and its
// signature: the fixed buffers the binding hands checkProbeSignature, laid out
// as the Security framework documents them (X9.63 point, ASN.1 DER ECDSA).
func probeVector(t *testing.T) (pub, digest, sig []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err = k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256(probeMessage)
	sig, err = ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return pub, d[:], sig
}

func TestCheckProbeSignature(t *testing.T) {
	pub, digest, sig := probeVector(t)
	if err := checkProbeSignature(pub, digest, sig); err != nil {
		t.Fatalf("a good signature: %v", err)
	}

	other, _, _ := probeVector(t)
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 1
	offCurve := make([]byte, 65)
	offCurve[0] = 4
	compressed := append([]byte{2}, pub[1:33]...)

	for name, c := range map[string]struct{ pub, sig []byte }{
		"signature altered":  {pub, bad},
		"another key":        {other, sig},
		"empty signature":    {pub, nil},
		"empty point":        {nil, sig},
		"short point":        {pub[:64], sig},
		"compressed point":   {compressed, sig},
		"point off curve":    {offCurve, sig},
		"point with a tail":  {append(append([]byte(nil), pub...), 0), sig},
		"not a DER sequence": {pub, sig[2:]},
	} {
		t.Run(name, func(t *testing.T) {
			err := checkProbeSignature(c.pub, digest, c.sig)
			var se *SecurityError
			if !errors.As(err, &se) || se.Op != OpVerify || se.Status != 0 {
				t.Fatalf("err = %v, want a *SecurityError at %q with no status", err, OpVerify)
			}
			if !errors.Is(err, ErrSecureEnclaveUnavailable) || errors.Is(err, ErrSecureEnclaveOperation) {
				t.Fatalf("err = %v, want only ErrSecureEnclaveUnavailable", err)
			}
		})
	}
}

func TestParsePublicX963(t *testing.T) {
	pub, _, _ := probeVector(t)
	k, err := parsePublicX963(pub)
	if err != nil {
		t.Fatal(err)
	}
	if k.Curve != elliptic.P256() {
		t.Fatalf("curve = %v, want P-256", k.Curve.Params().Name)
	}
	back, err := k.Bytes()
	if err != nil || string(back) != string(pub) {
		t.Fatalf("round trip = %x, %v; want %x", back, err, pub)
	}
}

package intelsgx

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

func TestAttestRefusesNonceLength(t *testing.T) {
	b := &Backend{}
	for _, n := range []int{0, reportDataSize + 1} {
		ev, err := b.Attest(context.Background(), make([]byte, n))
		if !errors.Is(err, enclave.ErrInvalidNonce) {
			t.Fatalf("Attest(%d-byte nonce) = %v, want ErrInvalidNonce", n, err)
		}
		if ev.Format != "" || ev.Data != nil {
			t.Fatalf("Attest(%d-byte nonce) evidence = %+v, want zero", n, ev)
		}
	}
	if _, err := b.Attest(context.Background(), nil); !errors.Is(err, enclave.ErrInvalidNonce) {
		t.Fatalf("Attest(nil) = %v, want ErrInvalidNonce", err)
	}
}

func TestPadNonce(t *testing.T) {
	for _, n := range []int{1, 32, reportDataSize} {
		in := bytes.Repeat([]byte{0xa5}, n)
		got, err := padNonce(in)
		if err != nil {
			t.Fatalf("padNonce(%d bytes) = %v", n, err)
		}
		if len(got) != reportDataSize {
			t.Fatalf("padNonce(%d bytes) length = %d, want %d", n, len(got), reportDataSize)
		}
		if !bytes.Equal(got[:n], in) {
			t.Fatalf("padNonce(%d bytes) prefix = %x, want %x", n, got[:n], in)
		}
		if !bytes.Equal(got[n:], make([]byte, reportDataSize-n)) {
			t.Fatalf("padNonce(%d bytes) tail = %x, want zeros", n, got[n:])
		}
		in[0] = 0
		if got[0] != 0xa5 {
			t.Fatalf("padNonce(%d bytes) aliases its input", n)
		}
	}
}

// TestAttestQuoteCarriesPaddedNonce lays a version 3 ECDSA quote out with a
// short nonce zero-padded at REPORT_DATA: checkQuote accepts it against the
// padded value and refuses the same quote against another nonce.
func TestAttestQuoteCarriesPaddedNonce(t *testing.T) {
	rd, err := padNonce([]byte("nonce"))
	if err != nil {
		t.Fatal(err)
	}
	q := quote(quoteVersion, keyTypeECDSAP256, rd)
	if err := checkQuote(q, rd); err != nil {
		t.Fatalf("checkQuote(padded nonce) = %v", err)
	}
	other, err := padNonce([]byte("other"))
	if err != nil {
		t.Fatal(err)
	}
	err = checkQuote(q, other)
	if !errors.Is(err, ErrReportDataMismatch) || !errors.Is(err, ErrSGXQuote) {
		t.Fatalf("checkQuote(other nonce) = %v, want ErrReportDataMismatch", err)
	}
}

func TestAttestEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&Backend{}).Attest(ctx, []byte{1}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Attest(canceled) = %v, want context.Canceled", err)
	}
}

// TestAttestRefusesOutsideEnclave runs the real Attest on a linux/amd64 host
// that is not in an SGX enclave, from many goroutines at once: each call
// refuses at attestation_type, under the backend's lock.
func TestAttestRefusesOutsideEnclave(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the stub's refusal is attest_other_test.go's")
	}
	skipInEnclave(t)
	b := &Backend{}
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = b.Attest(context.Background(), []byte{byte(i)})
		}()
	}
	wg.Wait()
	for _, err := range errs {
		var se *SGXEnclaveError
		if !errors.Is(err, ErrSGXUnavailable) || !errors.As(err, &se) || se.Op != "attestation_type" {
			t.Fatalf("Attest = %v, want an SGXEnclaveError with Op attestation_type", err)
		}
		if errors.Is(err, ErrSGXQuote) {
			t.Fatalf("Attest = %v matches ErrSGXQuote, want unavailable only", err)
		}
	}
}

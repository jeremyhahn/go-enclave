package intelsgx

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeAttestation stands a temporary directory in for Gramine's
// /dev/attestation: attestation_type reads dcap, user_report_data takes the
// report data, and readQuote returns a version 3 ECDSA quote over the report
// data last written, as the pseudo-file does. It tests this package's path
// from Attest to the quote; it proves nothing about SGX, which only the
// conformance test on the real part does.
func fakeAttestation(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "attestation_type"), []byte("dcap"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "user_report_data"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	oldDir, oldWrite, oldRead := attestationDir, writeReportData, readQuote
	t.Cleanup(func() { attestationDir, writeReportData, readQuote = oldDir, oldWrite, oldRead })
	attestationDir = dir
	writeReportData = func(data []byte) error {
		return os.WriteFile(filepath.Join(dir, "user_report_data"), data, 0o600)
	}
	readQuote = func(string) ([]byte, error) {
		rd, err := os.ReadFile(filepath.Join(dir, "user_report_data"))
		if err != nil {
			return nil, err
		}
		return quote(quoteVersion, keyTypeECDSAP256, rd), nil
	}
	return dir
}

func TestAttestReturnsQuoteBoundToEachNonce(t *testing.T) {
	fakeAttestation(t)
	b := newTestBackend()
	nonces := make([][]byte, 8)
	for i := range nonces {
		nonces[i] = []byte{'n', byte(i)}
	}
	quotes := make([][]byte, len(nonces))
	errs := make([]error, len(nonces))
	var wg sync.WaitGroup
	for i := range nonces {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev, err := b.Attest(context.Background(), nonces[i])
			if err == nil && ev.Format != EvidenceFormat {
				err = errors.New("evidence format " + ev.Format)
			}
			quotes[i], errs[i] = ev.Data, err
		}()
	}
	wg.Wait()
	for i := range nonces {
		if errs[i] != nil {
			t.Fatalf("Attest(nonce %d) = %v", i, errs[i])
		}
		rd, err := padNonce(nonces[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := checkQuote(quotes[i], rd); err != nil {
			t.Fatalf("quote for nonce %d does not bind it: %v", i, err)
		}
		other, err := padNonce(nonces[(i+1)%len(nonces)])
		if err != nil {
			t.Fatal(err)
		}
		if err := checkQuote(quotes[i], other); !errors.Is(err, ErrReportDataMismatch) {
			t.Fatalf("quote for nonce %d verifies against another nonce: %v", i, err)
		}
	}
}

func TestAttestRefusesQuoteOverOtherReportData(t *testing.T) {
	fakeAttestation(t)
	other, err := padNonce([]byte("written by another"))
	if err != nil {
		t.Fatal(err)
	}
	readQuote = func(string) ([]byte, error) { return quote(quoteVersion, keyTypeECDSAP256, other), nil }
	ev, err := newTestBackend().Attest(context.Background(), []byte("nonce"))
	var qe *SGXQuoteError
	if !errors.Is(err, ErrReportDataMismatch) || !errors.As(err, &qe) || qe.Op != "report_data" {
		t.Fatalf("Attest = %v, want an SGXQuoteError with Op report_data matching ErrReportDataMismatch", err)
	}
	if ev.Data != nil {
		t.Fatalf("Attest returned evidence with its error")
	}
}

func TestAttestRefusesMalformedQuote(t *testing.T) {
	fakeAttestation(t)
	readQuote = func(string) ([]byte, error) { return []byte{3, 0, 2, 0}, nil }
	_, err := newTestBackend().Attest(context.Background(), []byte("nonce"))
	var le *LayoutError
	if !errors.Is(err, ErrSGXQuote) || !errors.As(err, &le) {
		t.Fatalf("Attest = %v, want an SGXQuoteError carrying a LayoutError", err)
	}
}

func TestAttestEndedDuringReportDataWriteRequestsNoQuote(t *testing.T) {
	fakeAttestation(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	write := writeReportData
	writeReportData = func(data []byte) error {
		err := write(data)
		cancel()
		return err
	}
	var reads atomic.Int32
	readQuote = func(string) ([]byte, error) {
		reads.Add(1)
		return nil, errors.New("the quote was requested")
	}
	_, err := newTestBackend().Attest(ctx, []byte("nonce"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Attest = %v, want context.Canceled", err)
	}
	if n := reads.Load(); n != 0 {
		t.Fatalf("the quote was requested %d times after the context ended", n)
	}
}

func TestAttestEndedDuringQuoteReadReturnsContextError(t *testing.T) {
	dir := fakeAttestation(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readQuote = func(string) ([]byte, error) {
		rd, err := os.ReadFile(filepath.Join(dir, "user_report_data"))
		cancel()
		return quote(quoteVersion, keyTypeECDSAP256, rd), err
	}
	ev, err := newTestBackend().Attest(ctx, []byte("nonce"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Attest = %v, want context.Canceled", err)
	}
	if ev.Data != nil {
		t.Fatalf("Attest returned evidence after its context ended")
	}
}

func TestAttestWritesPaddedNonceAsReportData(t *testing.T) {
	dir := fakeAttestation(t)
	if _, err := newTestBackend().Attest(context.Background(), []byte("nonce")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "user_report_data"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := padNonce([]byte("nonce"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("user_report_data = %x, want %x", got, want)
	}
}

func TestUserReportDataPathIsInAttestationDir(t *testing.T) {
	if want := attestationDir + "/user_report_data"; userReportDataPath != want {
		t.Fatalf("userReportDataPath = %q, want %q", userReportDataPath, want)
	}
}

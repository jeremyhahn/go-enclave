package amdsev

import (
	"bytes"
	"context"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// TestNewRefusesOutsideAnSNPGuest: the constructor runs the probe's check, so
// outside an SNP guest no backend is built and the error says "not here". The
// in-guest pass belongs to the later slice that runs inside an SNP guest.
func TestNewRefusesOutsideAnSNPGuest(t *testing.T) {
	b, err := New(context.Background())
	if err == nil {
		t.Skip("this host is an SNP guest: the in-guest conformance run covers it")
	}
	if b != nil {
		t.Errorf("New returned a backend with error %v", err)
	}
	if !errors.Is(err, ErrSNPGuestUnavailable) || errors.Is(err, ErrSNPReport) {
		t.Errorf("New = %v, want an error matching ErrSNPGuestUnavailable only", err)
	}
	if perr := (&Backend{}).Probe(context.Background()); perr == nil || perr.Error() != err.Error() {
		t.Errorf("Probe = %v, want the constructor's verdict %v", perr, err)
	}
}

// TestZeroBackendRefusesImport: a Backend New did not build is no SNP
// guest's backend, so it neither claims confinement nor holds key material.
func TestZeroBackendRefusesImport(t *testing.T) {
	var b Backend
	if b.ConfinesProcess() {
		t.Error("zero Backend ConfinesProcess = true, want false")
	}
	material := []byte("secret material")
	h, err := b.Import(context.Background(), material, enclave.WithPurpose(enclave.PurposeMaterial))
	if h != nil {
		_ = h.Destroy()
	}
	if !errors.Is(err, ErrSNPGuestUnavailable) {
		t.Errorf("zero Backend Import = %v, want ErrSNPGuestUnavailable", err)
	}
	for i, c := range material {
		if c != 0 {
			t.Fatalf("Import left material byte %d set", i)
		}
	}
}

func TestNewEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("New(canceled) = %v, want context.Canceled", err)
	}
}

func TestBackendIdentity(t *testing.T) {
	var b enclave.Backend = &Backend{}
	if got := b.Name(); got != "amd-sev" || Name != "amd-sev" {
		t.Errorf("Name() = %q, want amd-sev", got)
	}
	p, ok := b.(enclave.Prober)
	if !ok || p.Rank() != 2 {
		t.Errorf("Backend is not a Prober of rank 2")
	}
	for name, ok := range map[string]bool{
		"Importer":     implements[enclave.Importer](b),
		"Attester":     implements[enclave.Attester](b),
		"Confiner":     implements[enclave.Confiner](b),
		"Sweeper":      implements[enclave.Sweeper](b),
		"RootUnsealer": implements[enclave.RootUnsealer](b),
	} {
		if !ok {
			t.Errorf("Backend does not implement enclave.%s", name)
		}
	}
	// A backend New did not build confines nothing.
	if (&Backend{}).ConfinesProcess() {
		t.Errorf("ConfinesProcess() = true on a backend New did not build")
	}
}

func implements[T any](v any) bool {
	_, ok := v.(T)
	return ok
}

func TestAttestRefusesBadNonce(t *testing.T) {
	for _, n := range []int{0, ReportDataSize + 1} {
		if _, err := (&Backend{}).Attest(context.Background(), make([]byte, n)); !errors.Is(err, enclave.ErrInvalidNonce) {
			t.Errorf("Attest(%d-byte nonce) = %v, want ErrInvalidNonce", n, err)
		}
	}
}

// TestAttestOutsideAnSNPGuest: with no report interface, Attest says "not
// here" rather than returning evidence of unknown provenance.
func TestAttestOutsideAnSNPGuest(t *testing.T) {
	ev, err := (&Backend{}).Attest(context.Background(), []byte("nonce"))
	if err == nil {
		t.Skip("this host is an SNP guest: the in-guest conformance run covers it")
	}
	if !errors.Is(err, ErrSNPGuestUnavailable) || ev.Data != nil {
		t.Errorf("Attest = %v, %d bytes; want ErrSNPGuestUnavailable and no evidence", err, len(ev.Data))
	}
}

func TestUnsealRootRefusesBeforeAnyRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dst := make([]byte, enclave.RootKeyBytes)
	if err := (&Backend{}).UnsealRoot(ctx, dst); !errors.Is(err, context.Canceled) {
		t.Errorf("UnsealRoot(ended ctx) = %v, want context.Canceled", err)
	}
	var ke *KeySizeError
	if err := (&Backend{}).UnsealRoot(context.Background(), make([]byte, 16)); !errors.As(err, &ke) || ke.Got != 16 {
		t.Errorf("UnsealRoot(16 bytes) = %v, want a *KeySizeError", err)
	}
}

// TestUnsealRootOutsideAnSNPGuest proves the refusal on a host with no
// /dev/sev-guest; the in-guest pass is a later slice on an SNP guest.
func TestUnsealRootOutsideAnSNPGuest(t *testing.T) {
	dst := make([]byte, enclave.RootKeyBytes)
	err := (&Backend{}).UnsealRoot(context.Background(), dst)
	if err == nil {
		t.Skip("this host is an SNP guest: the in-guest slice covers it")
	}
	if !errors.Is(err, ErrSNPGuestUnavailable) {
		t.Errorf("UnsealRoot = %v, want ErrSNPGuestUnavailable", err)
	}
	if !bytes.Equal(dst, make([]byte, enclave.RootKeyBytes)) {
		t.Errorf("a refused UnsealRoot wrote key material into dst")
	}
}

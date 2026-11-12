package inteltdx

import (
	"context"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

var (
	_ enclave.Prober   = (*Backend)(nil)
	_ enclave.Confiner = (*Backend)(nil)
)

// The constructor runs the probe: where the probe refuses, New returns the
// same typed error and no backend.
func TestNewRefusesWhereProbeRefuses(t *testing.T) {
	perr := probe(context.Background())
	if perr == nil {
		t.Skip("the probe passes on this host: the integration target covers New there")
	}
	b, err := New()
	if b != nil {
		t.Fatal("New returned a backend where the probe refuses")
	}
	if err == nil || err.Error() != perr.Error() {
		t.Fatalf("New() = %v, want the probe's %v", err, perr)
	}
	if !errors.Is(err, ErrGuestDeviceUnavailable) {
		t.Fatalf("New() = %v, want ErrGuestDeviceUnavailable", err)
	}
}

func TestIdentity(t *testing.T) {
	b := testBackend()
	if b.Name() != "intel-tdx" || Name != "intel-tdx" {
		t.Fatalf("Name() = %q, want intel-tdx", b.Name())
	}
	if b.Rank() != 10 {
		t.Fatalf("Rank() = %d, want 10", b.Rank())
	}
	if !b.ConfinesProcess() {
		t.Fatal("ConfinesProcess() = false: a constructed backend runs inside its TD")
	}
	var s enclave.Sweeper
	if enclave.As(b, &s) {
		t.Fatal("the backend is a Sweeper (Q7: memory enclaves are swept already)")
	}
	if (&Backend{}) == b {
		t.Fatal("two backends share an address")
	}
}

// testBackend is a backend as New returns it, without New's probe, so tests
// run off a TD.
func testBackend() *Backend { return &Backend{} }

// TestUnconstructedBackendRefuses: a Backend New did not make confines
// nothing and refuses Import and Attest with the typed unavailable error, so
// a sealer that requires erasure cannot accept it.
func TestUnconstructedBackendRefuses(t *testing.T) {
	b := &Backend{}
	if b.ConfinesProcess() {
		t.Fatal("ConfinesProcess() = true for a Backend New did not make")
	}
	material := make([]byte, 32)
	h, err := b.Import(context.Background(), material, enclave.WithPurpose(enclave.PurposeMaterial))
	if h != nil {
		_ = h.Destroy()
	}
	var gde *GuestDeviceError
	if h != nil || !errors.Is(err, ErrGuestDeviceUnavailable) || !errors.As(err, &gde) {
		t.Fatalf("Import on an unconstructed Backend = %v, %v; want nil, *GuestDeviceError", h, err)
	}
	if _, err := b.Attest(context.Background(), []byte{1}); !errors.Is(err, ErrGuestDeviceUnavailable) {
		t.Fatalf("Attest on an unconstructed Backend = %v, want ErrGuestDeviceUnavailable", err)
	}
}

func TestProbeMethodNilContext(t *testing.T) {
	b := &Backend{}
	if err := b.Probe(nil); err != nil && errors.Is(err, context.Canceled) {
		t.Fatalf("Probe(nil) = %v: a nil ctx never ends", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe(canceled) = %v, want context.Canceled", err)
	}
}

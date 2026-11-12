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
	b := &Backend{}
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

func TestProbeMethodNilContext(t *testing.T) {
	b := &Backend{}
	//nolint:staticcheck // a nil ctx is in the Prober contract
	if err := b.Probe(nil); err != nil && errors.Is(err, context.Canceled) {
		t.Fatalf("Probe(nil) = %v: a nil ctx never ends", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe(canceled) = %v, want context.Canceled", err)
	}
}

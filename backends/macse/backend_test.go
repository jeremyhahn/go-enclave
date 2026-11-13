package macse

import (
	"context"
	"errors"
	"sync"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// New runs the probe's check, so off the hardware it builds no backend.
func TestNew_RefusesWithoutTheBinding(t *testing.T) {
	b, err := New(context.Background())
	if b != nil {
		t.Fatalf("New = %v, want no backend", b)
	}
	var pe *PlatformError
	if !errors.Is(err, ErrSecureEnclaveUnavailable) || !errors.As(err, &pe) || pe.Op != OpCreate {
		t.Fatalf("New = %v, want a *PlatformError at %q", err, OpCreate)
	}
}

func TestBackend_NameRankProbe(t *testing.T) {
	var b Backend
	if b.Name() != "mac-secure-enclave" || b.Rank() != 2 {
		t.Fatalf("Name, Rank = %q, %d; want mac-secure-enclave, 2", b.Name(), b.Rank())
	}
	if err := b.Probe(context.Background()); !errors.Is(err, ErrSecureEnclaveUnavailable) {
		t.Fatalf("Probe = %v, want ErrSecureEnclaveUnavailable", err)
	}
	// The secure-element class takes no imports (the proposal's "Shape
	// proposed"): the backend is no Importer.
	if _, ok := any(&b).(enclave.Importer); ok {
		t.Fatal("Backend is an Importer")
	}
}

var (
	registerOnce sync.Once
	registerErr  error
)

// Registered by main, the backend loses Detect to a lower-ranked one here,
// and its refusal reaches main wrapped in a *ProbeError.
func TestDetect_PassesOverTheBackend(t *testing.T) {
	// The registry is the process's: register once across -count and -cpu
	// runs of this test.
	registerOnce.Do(func() { registerErr = enclave.Register(&Backend{}) })
	if err := registerErr; err != nil {
		t.Fatal(err)
	}
	chosen, results := enclave.Detect(context.Background())
	if chosen == nil || chosen.Name() == Name {
		t.Fatalf("Detect chose %v", chosen)
	}
	for _, r := range results {
		if r.Backend != Name {
			continue
		}
		var pe *enclave.ProbeError
		if r.Rank != 2 || !errors.As(r.Err, &pe) || !errors.Is(pe.Cause, ErrSecureEnclaveUnavailable) {
			t.Fatalf("result = %+v, want rank 2 and a *ProbeError matching ErrSecureEnclaveUnavailable", r)
		}
		return
	}
	t.Fatalf("Detect's results carry no %q: %+v", Name, results)
}

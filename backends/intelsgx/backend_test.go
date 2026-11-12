package intelsgx

import (
	"context"
	"errors"
	"testing"
)

// TestNewRefusesOutsideEnclave runs the real constructor on a host that is
// not in an SGX enclave (or not linux/amd64): it refuses with the typed
// unavailable error and builds no backend.
func TestNewRefusesOutsideEnclave(t *testing.T) {
	skipInEnclave(t)
	b, err := New(context.Background())
	if b != nil || !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("New = %v, %v; want nil, ErrSGXUnavailable", b, err)
	}
	var se *SGXEnclaveError
	if !errors.As(err, &se) || se.Op == "" {
		t.Fatalf("New = %v, want an SGXEnclaveError naming its step", err)
	}
	//nolint:staticcheck // SA1012: a nil ctx is documented as Background.
	if _, err := New(nil); !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("New(nil) = %v, want ErrSGXUnavailable", err)
	}
}

// TestBackendShape checks the fixed facts of a backend; the zero value is
// used because New refuses here.
func TestBackendShape(t *testing.T) {
	var b Backend
	if b.Name() != "intel-sgx" || b.Rank() != 2 || !b.ConfinesProcess() {
		t.Fatalf("Name, Rank, ConfinesProcess = %q, %d, %v; want intel-sgx, 2, true", b.Name(), b.Rank(), b.ConfinesProcess())
	}
	skipInEnclave(t)
	if err := b.Probe(context.Background()); !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("Probe = %v, want ErrSGXUnavailable", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := b.Probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Probe(cancelled) = %v, want context.Canceled", err)
	}
}

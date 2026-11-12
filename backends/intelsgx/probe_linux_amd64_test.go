//go:build linux && amd64

package intelsgx

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
)

// skipInEnclave skips a refusal test inside an enclave: there the probe
// passes, and the in-hardware conformance run covers it.
func skipInEnclave(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(attestationDir); err == nil {
		t.Skip(attestationDir + " exists: this process may be in an enclave")
	}
}

// TestProbeRefusesOutsideEnclave runs the real probe on a host that is not
// in an SGX enclave: it refuses at its first step, naming it.
func TestProbeRefusesOutsideEnclave(t *testing.T) {
	skipInEnclave(t)
	err := probe(context.Background())
	if !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("probe = %v, want ErrSGXUnavailable", err)
	}
	var se *SGXEnclaveError
	if !errors.As(err, &se) || se.Op != "attestation_type" {
		t.Fatalf("probe = %v, want an SGXEnclaveError with Op attestation_type", err)
	}
	var pe *fs.PathError
	if !errors.As(err, &pe) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("probe = %v, want a not-exist *fs.PathError cause", err)
	}
	if errors.Is(err, ErrSGXQuote) {
		t.Fatalf("probe = %v matches ErrSGXQuote, want unavailable only", err)
	}
}

func TestProbeEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("probe(canceled) = %v, want context.Canceled", err)
	}
}

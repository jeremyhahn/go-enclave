//go:build linux && amd64

package intelsgx

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
	"time"
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

// TestQuoteOverHonoursContextWhileLockHeld pins that a quote request waiting
// on the shared attestation lock returns at its own deadline instead of
// waiting out the request that holds the lock.
func TestQuoteOverHonoursContextWhileLockHeld(t *testing.T) {
	if err := lockAttestation(context.Background()); err != nil {
		t.Fatalf("lockAttestation: %v", err)
	}
	defer unlockAttestation()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := quoteOver(ctx, make([]byte, reportDataSize))
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("quoteOver = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("quoteOver waited on the held lock past its deadline")
	}
}

// TestQuoteOverEndedContext pins that quoteOver checks ctx after taking the
// lock and starts no request for an ended ctx.
func TestQuoteOverEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := quoteOver(ctx, make([]byte, reportDataSize))
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrSGXQuote) {
		t.Fatalf("quoteOver = %v, want context.Canceled and no request", err)
	}
}

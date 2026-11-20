package amdsev_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backends/amdsev"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// TestAmdSev_ConformanceConfigIsValid needs no hardware: backendtest checks
// its configuration before it constructs a backend, so a capability declared
// on the wrong side of the seam fails here, not first inside an SEV-SNP guest.
// The declarations match the backend module's own conformance test: the
// backend confines and imports, and its handle gives bytes and freezes.
func TestAmdSev_ConformanceConfigIsValid(t *testing.T) {
	cfg := conformance(t.Logf)
	err := backendtest.TestBackend(context.Background(), cfg)
	var ce *backendtest.ConfigError
	if errors.As(err, &ce) {
		t.Fatalf("backendtest rejects the configuration: %v", err)
	}
	for _, c := range []enclave.Capability{enclave.CapabilityConfine, enclave.CapabilityImport} {
		if !slices.Contains(cfg.BackendCapabilities, c) {
			t.Errorf("BackendCapabilities %v lacks %q", cfg.BackendCapabilities, c)
		}
	}
	for _, h := range cfg.Handles {
		for _, c := range []enclave.Capability{enclave.CapabilityBytes, enclave.CapabilityFreeze} {
			if !slices.Contains(h.Capabilities, c) {
				t.Errorf("handle %s: Capabilities %v lacks %q", h.Name, h.Capabilities, c)
			}
		}
	}
}

// TestAmdSev_NewBackendIsTheAmdsevBackend needs no hardware: wherever it runs,
// newBackend is the amdsev constructor. Off SEV-SNP it refuses with the
// backend's typed error and returns no backend; inside an SEV-SNP guest it
// returns the amdsev backend.
func TestAmdSev_NewBackendIsTheAmdsevBackend(t *testing.T) {
	b, err := newBackend()
	if err != nil {
		if b != nil || !errors.Is(err, amdsev.ErrSNPGuestUnavailable) {
			t.Fatalf("newBackend = %v, %v; want nil and an error that is amdsev.ErrSNPGuestUnavailable", b, err)
		}
		return
	}
	if b.Name() != amdsev.Name {
		t.Fatalf("newBackend built %q; want %q", b.Name(), amdsev.Name)
	}
}

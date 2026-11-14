package imxele

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestBackendIdentity(t *testing.T) {
	if got := (&Backend{}).Name(); got != "imx-edgelock-enclave" {
		t.Errorf("Backend.Name() = %q, want imx-edgelock-enclave", got)
	}
	if got := (Connector{}).Name(); got != Name {
		t.Errorf("Connector.Name() = %q, want %q", got, Name)
	}
	// Above arm-trustzone's 2 (Q3), so above linux-secretmem's 1 too.
	if got := (&Backend{}).Rank(); got <= 2 {
		t.Errorf("Rank() = %d, want above arm-trustzone's 2", got)
	}
}

// TestConnectRefusesWithoutDevice: construction runs the probe's check and
// never falls back; without the device it returns the typed refusal.
func TestConnectRefusesWithoutDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tee0")
	b, err := Connect(path)
	var de *TEEDeviceError
	if b != nil || !errors.As(err, &de) || !errors.Is(err, ErrTEEDeviceUnavailable) || de.Path != path {
		t.Fatalf("Connect = %v, %v; want a *TEEDeviceError for %s", b, err, path)
	}
	cb, err := (Connector{}).Connect(path)
	if cb != nil || !errors.Is(err, ErrTEEDeviceUnavailable) {
		t.Fatalf("Connector.Connect = %v, %v; want ErrTEEDeviceUnavailable", cb, err)
	}
}

// TestProbeMethodRefusesWithoutDevice: the zero Backend, as a main registers
// it for Detect, probes the default device; one made for a path probes it.
func TestProbeMethodRefusesWithoutDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tee0")
	err := (&Backend{endpoint: path}).Probe(context.Background())
	var de *TEEDeviceError
	if !errors.As(err, &de) || de.Path != path {
		t.Fatalf("Probe = %v, want a *TEEDeviceError for %s", err, path)
	}
	if err := (&Backend{}).Probe(context.Background()); err == nil {
		t.Fatalf("Probe of the default device succeeded before the session step exists")
	}
}

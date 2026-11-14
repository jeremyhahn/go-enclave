//go:build linux

package imxele

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestProbeRefusesAbsentDevice proves the refusal path for real: no device
// at the path, so the open step refuses with ENOENT.
func TestProbeRefusesAbsentDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tee0")
	err := probe(context.Background(), path)
	var de *TEEDeviceError
	if !errors.As(err, &de) || !errors.Is(err, ErrTEEDeviceUnavailable) {
		t.Fatalf("probe = %v, want a *TEEDeviceError", err)
	}
	if de.Path != path || de.Op != "open" || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("probe = %+v, want the open step refused with ENOENT", de)
	}
	var se *os.SyscallError
	if !errors.As(err, &se) {
		t.Fatalf("probe cause = %v, want an *os.SyscallError", de.Cause)
	}
}

// TestProbeRefusesNonDevice opens a regular file, which the kernel refuses
// TEE_IOC_VERSION on (ENOTTY): the version step names the refusal.
func TestProbeRefusesNonDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-device")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := probe(context.Background(), path)
	var de *TEEDeviceError
	if !errors.As(err, &de) || de.Op != "version" || !errors.Is(err, syscall.ENOTTY) {
		t.Fatalf("probe = %v, want the version step refused with ENOTTY", err)
	}
}

// TestProbeOnThisHost probes the default device. Without the hardware the
// open step refuses; with it, the session step refuses until trusted-imx95
// publishes its ABI (the in-hardware run is a later slice).
func TestProbeOnThisHost(t *testing.T) {
	err := probe(context.Background(), DefaultEndpoint)
	if _, statErr := os.Stat(DefaultEndpoint); statErr != nil {
		var de *TEEDeviceError
		if !errors.As(err, &de) || de.Op != "open" || de.Path != DefaultEndpoint {
			t.Fatalf("probe = %v, want the open step of %s refused", err, DefaultEndpoint)
		}
		return
	}
	if !errors.Is(err, ErrTEEDeviceUnavailable) && !errors.Is(err, ErrTEESessionUnavailable) {
		t.Fatalf("probe = %v, want a device or session refusal", err)
	}
}

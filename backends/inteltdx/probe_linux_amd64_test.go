package inteltdx

import (
	"context"
	"errors"
	"os"
	"syscall"
	"testing"
)

// skipInTD skips where the guest device exists: inside a TD the refusal path
// does not run, and the integration target proves the device paths there.
func skipInTD(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(guestDevice); err == nil {
		t.Skip(guestDevice + " is present: the device paths are the integration target's")
	}
}

// On a host that is not a TD the probe stops at its first step, opening the
// guest device, with the real ENOENT.
func TestProbeRefusesOffTD(t *testing.T) {
	skipInTD(t)
	err := probe(context.Background())
	var ge *GuestDeviceError
	if !errors.As(err, &ge) || ge.Op != "open" {
		t.Fatalf("probe() = %v, want a GuestDeviceError at open", err)
	}
	if !errors.Is(err, ErrGuestDeviceUnavailable) || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("probe() = %v, want ErrGuestDeviceUnavailable wrapping ENOENT", err)
	}
}

func TestProbeEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("probe(canceled) = %v, want context.Canceled", err)
	}
}

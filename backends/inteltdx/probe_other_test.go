//go:build !(linux && amd64)

package inteltdx

import (
	"context"
	"errors"
	"runtime"
	"testing"
)

// Off linux/amd64 the stub refuses with the typed unavailable error and no
// cause.
func TestProbeRefusesPlatform(t *testing.T) {
	err := probe(context.Background())
	var ge *GuestDeviceError
	if !errors.As(err, &ge) || ge.Cause != nil {
		t.Fatalf("probe() = %v, want a GuestDeviceError without a cause", err)
	}
	if want := "platform " + runtime.GOOS + "/" + runtime.GOARCH; ge.Op != want {
		t.Fatalf("Op = %q, want %q", ge.Op, want)
	}
	if !errors.Is(err, ErrGuestDeviceUnavailable) {
		t.Fatalf("probe() = %v, want ErrGuestDeviceUnavailable", err)
	}
}

func TestProbeEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probe(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("probe(canceled) = %v, want context.Canceled", err)
	}
}

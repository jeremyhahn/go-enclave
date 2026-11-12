//go:build !(linux && amd64)

package inteltdx

import (
	"context"
	"errors"
	"runtime"
	"testing"
)

// Off linux/amd64 the stub's Attest refuses with the typed unavailable error
// and no cause, after the nonce check.
func TestAttestRefusesPlatform(t *testing.T) {
	ev, err := (&Backend{}).Attest(context.Background(), []byte("nonce"))
	var ge *GuestDeviceError
	if !errors.As(err, &ge) || ge.Cause != nil {
		t.Fatalf("Attest() = %v, want a GuestDeviceError without a cause", err)
	}
	if want := "platform " + runtime.GOOS + "/" + runtime.GOARCH; ge.Op != want {
		t.Fatalf("Op = %q, want %q", ge.Op, want)
	}
	if !errors.Is(err, ErrGuestDeviceUnavailable) {
		t.Fatalf("Attest() = %v, want ErrGuestDeviceUnavailable", err)
	}
	if ev.Format != "" || ev.Data != nil {
		t.Fatalf("Attest() evidence = %+v on error, want zero", ev)
	}
}

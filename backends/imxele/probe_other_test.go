//go:build !linux

package imxele

import (
	"context"
	"errors"
	"testing"
)

func TestProbeRefusesOffLinux(t *testing.T) {
	err := probe(context.Background(), DefaultEndpoint)
	var de *TEEDeviceError
	if !errors.As(err, &de) || !errors.Is(err, ErrTEEDeviceUnavailable) || de.Op != "platform" || de.Cause != nil {
		t.Fatalf("probe = %v, want the platform step refused with no cause", err)
	}
}

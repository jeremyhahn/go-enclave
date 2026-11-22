//go:build !(linux && amd64)

package intelsgx

import (
	"context"
	"errors"
	"testing"
)

// outsideEnclave has nothing to point here: this build is never in an enclave.
func outsideEnclave(*testing.T) {}

func TestProbeRefusesPlatform(t *testing.T) {
	err := probe(context.Background())
	var se *SGXEnclaveError
	if !errors.As(err, &se) || se.Op != "platform" || se.Cause != nil || !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("probe = %v, want an SGXEnclaveError with Op platform and no cause", err)
	}
}

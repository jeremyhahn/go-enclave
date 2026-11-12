//go:build !(linux && amd64)

package intelsgx

import (
	"context"
	"errors"
	"testing"
)

// skipInEnclave never skips here: no enclave runs this build.
func skipInEnclave(*testing.T) {}

func TestProbeRefusesPlatform(t *testing.T) {
	err := probe(context.Background())
	var se *SGXEnclaveError
	if !errors.As(err, &se) || se.Op != "platform" || se.Cause != nil || !errors.Is(err, ErrSGXUnavailable) {
		t.Fatalf("probe = %v, want an SGXEnclaveError with Op platform and no cause", err)
	}
}

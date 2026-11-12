//go:build !(linux && amd64)

package intelsgx

import (
	"context"
	"errors"
	"testing"
)

func TestAttestRefusesPlatform(t *testing.T) {
	_, err := (&Backend{}).Attest(context.Background(), []byte{1})
	var se *SGXEnclaveError
	if !errors.Is(err, ErrSGXUnavailable) || !errors.As(err, &se) || se.Op != "platform" {
		t.Fatalf("Attest = %v, want an SGXEnclaveError with Op platform", err)
	}
	if se.Cause != nil {
		t.Fatalf("Attest cause = %v, want none", se.Cause)
	}
}

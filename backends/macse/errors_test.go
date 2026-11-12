package macse

import (
	"context"
	"errors"
	"testing"
)

func TestStatusText(t *testing.T) {
	for status, want := range map[int32]string{
		-50:    "errSecParam (-50)",
		-4:     "errSecUnimplemented (-4)",
		-25308: "errSecInteractionNotAllowed (-25308)",
		-1:     "OSStatus -1",
		7:      "OSStatus 7",
	} {
		if got := statusText(status); got != want {
			t.Errorf("statusText(%d) = %q, want %q", status, got, want)
		}
	}
}

func TestSecurityError(t *testing.T) {
	err := error(unavailableError(OpCreate, -50, context.DeadlineExceeded))
	want := "macse: create: secure enclave unavailable: errSecParam (-50): context deadline exceeded"
	if err.Error() != want {
		t.Fatalf("Error() = %q, want %q", err, want)
	}
	if !errors.Is(err, ErrSecureEnclaveUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v does not match its class and cause", err)
	}
	if errors.Is(err, ErrSecureEnclaveOperation) {
		t.Fatalf("%v matches ErrSecureEnclaveOperation", err)
	}

	bare := &SecurityError{Op: OpSign}
	if bare.Error() != "macse: sign" || errors.Is(bare, ErrSecureEnclaveUnavailable) || errors.Is(bare, ErrSecureEnclaveOperation) {
		t.Fatalf("a literal with no class: %q", bare)
	}
}

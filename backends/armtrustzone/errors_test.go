package armtrustzone

import (
	"errors"
	"fmt"
	"testing"
)

// The error contract table for every exported error type and sentinel is
// TestErrorContract in errors_contract_test.go; this file holds the
// helpers' own tests.

func TestDeviceErrorUnwrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("cause")
	e := &DeviceError{Endpoint: "/dev/tee0", Op: "invoke", Cause: cause}
	if got := e.Unwrap(); got != cause { //nolint:errorlint // identity check of Unwrap
		t.Errorf("Unwrap() = %v, want %v", got, cause)
	}
	if !errors.Is(e, cause) {
		t.Error("errors.Is(DeviceError, Cause) = false, want true")
	}
	if got := (&DeviceError{}).Unwrap(); got != nil {
		t.Errorf("Unwrap() with nil Cause = %v, want nil", got)
	}
	bare := &DeviceError{Endpoint: "/dev/tee0", Op: "open"}
	if got, want := bare.Error(), `armtrustzone: the TEE device is unavailable: "/dev/tee0": open`; got != want {
		t.Errorf("Error() with nil Cause = %q, want %q", got, want)
	}
	nested := &DeviceError{Endpoint: "/dev/tee0", Op: "version", Cause: fmt.Errorf("ctx: %w", ErrNotGlobalPlatform)}
	if !errors.Is(fmt.Errorf("outer: %w", nested), ErrNotGlobalPlatform) {
		t.Error("errors.Is did not reach ErrNotGlobalPlatform through a wrapped DeviceError")
	}
}

func TestHex32(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0x00000000"},
		{1, "0x00000001"},
		{0xdeadbeef, "0xdeadbeef"},
		{0xffffffff, "0xffffffff"},
		{0x1_0000_0000, "0x100000000"},
		{0xdead_beef_cafe, "0xdeadbeefcafe"},
	}
	for _, tt := range tests {
		if got := hex32(tt.in); got != tt.want {
			t.Errorf("hex32(%#x) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestResultText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code, origin uint32
		want         string
	}{
		{0, 0, "result 0x00000000, origin 0"},
		{0xffff0006, 3, "result 0xffff0006, origin 3"},
		{0xdeadbeef, 0xffffffff, "result 0xdeadbeef, origin 4294967295"},
	}
	for _, tt := range tests {
		if got := resultText(tt.code, tt.origin); got != tt.want {
			t.Errorf("resultText(%#x, %d) = %q, want %q", tt.code, tt.origin, got, tt.want)
		}
	}
}

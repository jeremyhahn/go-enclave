package armtrustzone

import (
	"errors"
	"fmt"
	"testing"
)

// allSentinels is every sentinel errors.go declares.
var allSentinels = map[string]error{
	"ErrUnsupportedPlatform":  ErrUnsupportedPlatform,
	"ErrDeviceUnavailable":    ErrDeviceUnavailable,
	"ErrNotGlobalPlatform":    ErrNotGlobalPlatform,
	"ErrSessionRefused":       ErrSessionRefused,
	"ErrCommandFailed":        ErrCommandFailed,
	"ErrInterfaceUnsupported": ErrInterfaceUnsupported,
	"ErrRandomSize":           ErrRandomSize,
	"ErrShortRandom":          ErrShortRandom,
	"ErrInvalidUUID":          ErrInvalidUUID,
	"ErrBackendClosed":        ErrBackendClosed,
}

// asOwn reports whether errors.As finds a T in err and the found value is want.
func asOwn[T error](err error, want T) bool {
	var got T
	return errors.As(err, &got) && any(got) == any(want)
}

func TestErrorTypesContract(t *testing.T) {
	t.Parallel()

	platform := &PlatformError{GOOS: "plan9"}
	device := &DeviceError{Endpoint: "/dev/tee0", Op: "version", Cause: ErrNotGlobalPlatform}
	deviceNil := &DeviceError{Endpoint: "/dev/tee0", Op: "open"}
	session := &SessionError{Code: 0xffff0008, Origin: 3}
	command := &CommandError{Command: 2, Code: 0xffff000c, Origin: 4}
	iface := &InterfaceError{Version: 7, Flags: 0x1}
	size := &SizeError{N: -1}
	short := &ShortRandomError{Want: 32, Got: 16}
	uuid := &UUIDError{Text: "not-a-uuid"}

	tests := []struct {
		name  string
		err   error
		text  string
		match []string // sentinels errors.Is must report; every other one must be refused
		as    func(error) bool
	}{
		{
			name:  "PlatformError",
			err:   platform,
			text:  `armtrustzone: the Linux TEE subsystem is not available on this platform: "plan9"`,
			match: []string{"ErrUnsupportedPlatform"},
			as:    func(e error) bool { return asOwn(e, platform) },
		},
		{
			name:  "DeviceError",
			err:   device,
			text:  `armtrustzone: the TEE device is unavailable: "/dev/tee0": version: armtrustzone: the TEE is not GlobalPlatform compliant`,
			match: []string{"ErrDeviceUnavailable", "ErrNotGlobalPlatform"},
			as:    func(e error) bool { return asOwn(e, device) },
		},
		{
			name:  "DeviceError nil Cause",
			err:   deviceNil,
			text:  `armtrustzone: the TEE device is unavailable: "/dev/tee0": open`,
			match: []string{"ErrDeviceUnavailable"},
			as:    func(e error) bool { return asOwn(e, deviceNil) },
		},
		{
			name:  "SessionError",
			err:   session,
			text:  "armtrustzone: the TEE refused a session with the trusted application: result 0xffff0008, origin 3",
			match: []string{"ErrSessionRefused"},
			as:    func(e error) bool { return asOwn(e, session) },
		},
		{
			name:  "CommandError",
			err:   command,
			text:  "armtrustzone: the trusted application's command failed: command 0x00000002: result 0xffff000c, origin 4",
			match: []string{"ErrCommandFailed"},
			as:    func(e error) bool { return asOwn(e, command) },
		},
		{
			name:  "InterfaceError",
			err:   iface,
			text:  "armtrustzone: the trusted application's interface is not supported: version 7, flags 0x00000001",
			match: []string{"ErrInterfaceUnsupported"},
			as:    func(e error) bool { return asOwn(e, iface) },
		},
		{
			name:  "SizeError",
			err:   size,
			text:  "armtrustzone: a random request must be at least one byte: -1",
			match: []string{"ErrRandomSize"},
			as:    func(e error) bool { return asOwn(e, size) },
		},
		{
			name:  "ShortRandomError",
			err:   short,
			text:  "armtrustzone: the trusted application returned fewer random bytes than asked: want 32, got 16",
			match: []string{"ErrShortRandom"},
			as:    func(e error) bool { return asOwn(e, short) },
		},
		{
			name:  "UUIDError",
			err:   uuid,
			text:  `armtrustzone: not an RFC 9562 UUID: "not-a-uuid"`,
			match: []string{"ErrInvalidUUID"},
			as:    func(e error) bool { return asOwn(e, uuid) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.err.Error(); got != tt.text {
				t.Errorf("Error() = %q, want %q", got, tt.text)
			}

			wrapped := fmt.Errorf("wrap: %w", tt.err)
			for name, sentinel := range allSentinels {
				want := false
				for _, m := range tt.match {
					if m == name {
						want = true
					}
				}
				if got := errors.Is(tt.err, sentinel); got != want {
					t.Errorf("errors.Is(err, %s) = %v, want %v", name, got, want)
				}
				if got := errors.Is(wrapped, sentinel); got != want {
					t.Errorf("errors.Is(wrapped, %s) = %v, want %v", name, got, want)
				}
			}

			if !tt.as(wrapped) {
				t.Errorf("errors.As(wrapped, *%s) did not find the original value", tt.name)
			}
		})
	}
}

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

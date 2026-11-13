package imxele

import (
	"errors"
	"fmt"
	"runtime"
)

// The typed errors of docs/backends/imx-edgelock-enclave.md "Failure modes",
// named for the mechanism (the TEE client session and its commands). Each
// struct error matches its sentinel with errors.Is and unwraps to its cause,
// so the errno a refused call returned stays reachable.
var (
	// ErrTEEDeviceUnavailable is matched by a [*TEEDeviceError]: the TEE
	// device is absent, refused, not a GlobalPlatform client, or the platform
	// has no TEE subsystem.
	ErrTEEDeviceUnavailable = errors.New("imxele: TEE device unavailable")
	// ErrTEESessionUnavailable is matched by a [*TEESessionError]: no session
	// to trusted-imx95's trusted application could be opened.
	ErrTEESessionUnavailable = errors.New("imxele: TEE session unavailable")
	// ErrABIVersionUnsupported is matched by an [*ABIVersionError].
	ErrABIVersionUnsupported = errors.New("imxele: trusted application ABI version unsupported")
	// ErrTEECommandFailed is matched by a [*TEECommandError].
	ErrTEECommandFailed = errors.New("imxele: TEE command failed")
	// ErrNotGlobalPlatform is the cause of a [*TEEDeviceError] for the
	// "version" step when the driver does not report a GlobalPlatform client.
	ErrNotGlobalPlatform = errors.New("imxele: TEE driver is not a GlobalPlatform client")
)

// errTAUnpublished is the cause of the [*TEESessionError] the probe returns
// until trusted-imx95 publishes its trusted application's UUID and command
// ABI: the backend refuses rather than guess them.
var errTAUnpublished = errors.New("trusted-imx95 has published no trusted application UUID or command ABI")

// TEEDeviceError reports a refused step on the TEE device. It matches
// [ErrTEEDeviceUnavailable].
type TEEDeviceError struct {
	// Path is the device path, such as "/dev/tee0".
	Path string
	// Op is the refused step: "open", "version", "close", or "platform" when
	// the platform has no TEE subsystem.
	Op string
	// Cause is the refused call's *os.SyscallError, [ErrNotGlobalPlatform],
	// or nil for the "platform" step.
	Cause error
}

func (e *TEEDeviceError) Error() string {
	if e.Cause == nil {
		return fmt.Sprintf("imxele: %s: %s: no TEE device on %s/%s", e.Path, e.Op, runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("imxele: %s: %s: %v", e.Path, e.Op, e.Cause)
}

// Is reports whether target is [ErrTEEDeviceUnavailable].
func (e *TEEDeviceError) Is(target error) bool { return target == ErrTEEDeviceUnavailable }

// Unwrap returns the cause.
func (e *TEEDeviceError) Unwrap() error { return e.Cause }

// TEESessionError reports a session the TEE refused to open. It matches
// [ErrTEESessionUnavailable].
type TEESessionError struct {
	// UUID is the trusted application's UUID, empty until it is published.
	UUID string
	// Code and Origin are the TEE Client API's result and return origin.
	Code, Origin uint32
	// Cause is why no session was attempted, or nil when the TEE refused one.
	Cause error
}

func (e *TEESessionError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("imxele: open-session %q: %v", e.UUID, e.Cause)
	}
	return fmt.Sprintf("imxele: open-session %q: result 0x%08x, origin %d", e.UUID, e.Code, e.Origin)
}

// Is reports whether target is [ErrTEESessionUnavailable].
func (e *TEESessionError) Is(target error) bool { return target == ErrTEESessionUnavailable }

// Unwrap returns the cause.
func (e *TEESessionError) Unwrap() error { return e.Cause }

// ABIVersionError reports a trusted application ABI version the backend
// does not speak. It matches [ErrABIVersionUnsupported].
type ABIVersionError struct {
	Got, Want uint32
}

func (e *ABIVersionError) Error() string {
	return fmt.Sprintf("imxele: trusted application ABI version %d, want %d", e.Got, e.Want)
}

// Is reports whether target is [ErrABIVersionUnsupported].
func (e *ABIVersionError) Is(target error) bool { return target == ErrABIVersionUnsupported }

// TEECommandError reports a command that failed in the secure world, or
// outlived the backend's timeout. It matches [ErrTEECommandFailed].
type TEECommandError struct {
	// Command is the trusted application's command ID.
	Command uint32
	// Code and Origin are the TEE Client API's result and return origin.
	Code, Origin uint32
	// Cause is context.DeadlineExceeded for a timeout, the refused ioctl's
	// *os.SyscallError, or nil when the secure world returned Code.
	Cause error
}

func (e *TEECommandError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("imxele: command %d: %v", e.Command, e.Cause)
	}
	return fmt.Sprintf("imxele: command %d: result 0x%08x, origin %d", e.Command, e.Code, e.Origin)
}

// Is reports whether target is [ErrTEECommandFailed].
func (e *TEECommandError) Is(target error) bool { return target == ErrTEECommandFailed }

// Unwrap returns the cause.
func (e *TEECommandError) Unwrap() error { return e.Cause }

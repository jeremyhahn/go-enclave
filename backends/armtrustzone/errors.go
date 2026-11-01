package armtrustzone

import (
	"errors"
	"strconv"
)

// Every failure of this module is one of the sentinels below or a type that
// matches one with errors.Is; read a type's fields with errors.As.

// ErrUnsupportedPlatform reports a build for a platform without the Linux TEE
// subsystem: the backend runs on linux only. Every [PlatformError] matches it.
var ErrUnsupportedPlatform = errors.New("armtrustzone: the Linux TEE subsystem is not available on this platform")

// PlatformError is the error behind [ErrUnsupportedPlatform].
type PlatformError struct {
	// GOOS is the platform the module was built for.
	GOOS string
}

// Error is [ErrUnsupportedPlatform]'s text and the quoted GOOS.
func (e *PlatformError) Error() string {
	return ErrUnsupportedPlatform.Error() + ": " + strconv.Quote(e.GOOS)
}

// Is reports every PlatformError as [ErrUnsupportedPlatform].
func (e *PlatformError) Is(target error) bool { return target == ErrUnsupportedPlatform }

// ErrDeviceUnavailable reports that the TEE device refused the backend: it is
// missing or refuses the process, a TEE ioctl failed, or it is not a
// GlobalPlatform TEE ([ErrNotGlobalPlatform]). Every [DeviceError] matches it.
var ErrDeviceUnavailable = errors.New("armtrustzone: the TEE device is unavailable")

// ErrNotGlobalPlatform reports a TEE device that does not claim
// TEE_GEN_CAP_GP, so the GP TEE Client API's semantics do not hold on it. It
// is the Cause of a [DeviceError].
var ErrNotGlobalPlatform = errors.New("armtrustzone: the TEE is not GlobalPlatform compliant")

// DeviceError is the error behind [ErrDeviceUnavailable].
type DeviceError struct {
	// Endpoint is the device path, such as "/dev/tee0".
	Endpoint string
	// Op is the refused step: "open", "version", "open-session", "invoke",
	// "shm-alloc", "mmap", "close-session" or "close".
	Op string
	// Cause is the refused call's *os.SyscallError, or [ErrNotGlobalPlatform].
	Cause error
}

// Error is [ErrDeviceUnavailable]'s text, the endpoint, the step and the cause.
func (e *DeviceError) Error() string {
	msg := ErrDeviceUnavailable.Error() + ": " + strconv.Quote(e.Endpoint) + ": " + e.Op
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Is reports every DeviceError as [ErrDeviceUnavailable].
func (e *DeviceError) Is(target error) bool { return target == ErrDeviceUnavailable }

// Unwrap returns the cause.
func (e *DeviceError) Unwrap() error { return e.Cause }

// ErrSessionRefused reports that the TEE refused a session with the trusted
// application: the TA is missing (TEEC_ERROR_ITEM_NOT_FOUND) or refused the
// client. Every [SessionError] matches it.
var ErrSessionRefused = errors.New("armtrustzone: the TEE refused a session with the trusted application")

// SessionError is the error behind [ErrSessionRefused].
type SessionError struct {
	// Code is the TEEC_Result the TEE returned.
	Code uint32
	// Origin is the TEEC_ORIGIN_* the code came from.
	Origin uint32
}

// Error is [ErrSessionRefused]'s text with the code and the origin.
func (e *SessionError) Error() string {
	return ErrSessionRefused.Error() + ": " + resultText(e.Code, e.Origin)
}

// Is reports every SessionError as [ErrSessionRefused].
func (e *SessionError) Is(target error) bool { return target == ErrSessionRefused }

// ErrCommandFailed reports a command the trusted application did not complete:
// TEEC_InvokeCommand returned a code other than TEEC_SUCCESS. Every
// [CommandError] matches it.
var ErrCommandFailed = errors.New("armtrustzone: the trusted application's command failed")

// CommandError is the error behind [ErrCommandFailed].
type CommandError struct {
	// Command is the TA command id, such as TFW_TA_CMD_GET_RANDOM.
	Command uint32
	// Code is the TEEC_Result the TEE returned.
	Code uint32
	// Origin is the TEEC_ORIGIN_* the code came from.
	Origin uint32
}

// Error is [ErrCommandFailed]'s text with the command, the code and the origin.
func (e *CommandError) Error() string {
	return ErrCommandFailed.Error() + ": command " + hex32(uint64(e.Command)) + ": " + resultText(e.Code, e.Origin)
}

// Is reports every CommandError as [ErrCommandFailed].
func (e *CommandError) Is(target error) bool { return target == ErrCommandFailed }

// ErrInterfaceUnsupported reports a trusted application whose GET_INFO is not
// interface version 1 with flags 0, the only interface this client drives.
// Every [InterfaceError] matches it.
var ErrInterfaceUnsupported = errors.New("armtrustzone: the trusted application's interface is not supported")

// InterfaceError is the error behind [ErrInterfaceUnsupported].
type InterfaceError struct {
	// Version is the interface version GET_INFO reported, as the 64-bit
	// value field the kernel returned it in.
	Version uint64
	// Flags are the flags GET_INFO reported, as the 64-bit value field the
	// kernel returned them in.
	Flags uint64
}

// Error is [ErrInterfaceUnsupported]'s text with the version and the flags.
func (e *InterfaceError) Error() string {
	return ErrInterfaceUnsupported.Error() + ": version " + strconv.FormatUint(e.Version, 10) +
		", flags " + hex32(e.Flags)
}

// Is reports every InterfaceError as [ErrInterfaceUnsupported].
func (e *InterfaceError) Is(target error) bool { return target == ErrInterfaceUnsupported }

// ErrRandomSize reports a Random request for fewer than one byte; it is
// refused before the trusted application is called. Every [SizeError]
// matches it.
var ErrRandomSize = errors.New("armtrustzone: a random request must be at least one byte")

// SizeError is the error behind [ErrRandomSize].
type SizeError struct {
	// N is the refused size.
	N int
}

// Error is [ErrRandomSize]'s text with the refused size.
func (e *SizeError) Error() string { return ErrRandomSize.Error() + ": " + strconv.Itoa(e.N) }

// Is reports every SizeError as [ErrRandomSize].
func (e *SizeError) Is(target error) bool { return target == ErrRandomSize }

// ErrShortRandom reports that GET_RANDOM wrote fewer bytes than its chunk
// asked for. Every [ShortRandomError] matches it.
var ErrShortRandom = errors.New("armtrustzone: the trusted application returned fewer random bytes than asked")

// ShortRandomError is the error behind [ErrShortRandom].
type ShortRandomError struct {
	// Want is the chunk's size and Got what the TA reported writing.
	Want, Got uint64
}

// Error is [ErrShortRandom]'s text with both sizes.
func (e *ShortRandomError) Error() string {
	return ErrShortRandom.Error() + ": want " + strconv.FormatUint(e.Want, 10) + ", got " + strconv.FormatUint(e.Got, 10)
}

// Is reports every ShortRandomError as [ErrShortRandom].
func (e *ShortRandomError) Is(target error) bool { return target == ErrShortRandom }

// ErrInvalidUUID reports text that is not an RFC 9562 UUID in its string
// form. Every [UUIDError] matches it.
var ErrInvalidUUID = errors.New("armtrustzone: not an RFC 9562 UUID")

// UUIDError is the error behind [ErrInvalidUUID].
type UUIDError struct {
	// Text is the refused text.
	Text string
}

// Error is [ErrInvalidUUID]'s text with the quoted text.
func (e *UUIDError) Error() string { return ErrInvalidUUID.Error() + ": " + strconv.Quote(e.Text) }

// Is reports every UUIDError as [ErrInvalidUUID].
func (e *UUIDError) Is(target error) bool { return target == ErrInvalidUUID }

// ErrBackendClosed reports a call on a [Backend] after its Close.
var ErrBackendClosed = errors.New("armtrustzone: the backend is closed")

// resultText formats a TEEC_Result and its origin.
func resultText(code, origin uint32) string {
	return "result " + hex32(uint64(code)) + ", origin " + strconv.FormatUint(uint64(origin), 10)
}

// hex32 formats v as 0x and at least eight hex digits.
func hex32(v uint64) string {
	s := strconv.FormatUint(v, 16)
	for len(s) < 8 {
		s = "0" + s
	}
	return "0x" + s
}

package tpm

import (
	"errors"
	"strconv"

	"github.com/google/go-tpm/tpm2"

	enclave "github.com/jeremyhahn/go-enclave"
)

// ErrUnsupportedPlatform reports that the provider cannot open a TPM on this
// platform: only Linux has the kernel's TPM resource manager.
var ErrUnsupportedPlatform = errors.New("tpm: the TPM provider is not available on this platform")

// PlatformError is the error behind [ErrUnsupportedPlatform].
type PlatformError struct {
	// GOOS is the platform the module was built for.
	GOOS string
}

// Error implements error.
func (e *PlatformError) Error() string {
	return ErrUnsupportedPlatform.Error() + ": " + strconv.Quote(e.GOOS)
}

// Is reports whether target is [ErrUnsupportedPlatform].
func (e *PlatformError) Is(target error) bool { return target == ErrUnsupportedPlatform }

// ErrDeviceUnavailable reports that the TPM device could not be opened, read
// or written.
var ErrDeviceUnavailable = errors.New("tpm: the TPM device is unavailable")

// DeviceError is the error behind [ErrDeviceUnavailable].
type DeviceError struct {
	// Path is the device or socket the provider opened.
	Path string
	// Op is the operation that failed: "open", "read" or "write".
	Op string
	// Err is the underlying error.
	Err error
}

// Error implements error.
func (e *DeviceError) Error() string {
	s := ErrDeviceUnavailable.Error() + ": " + e.Op + " " + strconv.Quote(e.Path)
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Is reports whether target is [ErrDeviceUnavailable].
func (e *DeviceError) Is(target error) bool { return target == ErrDeviceUnavailable }

// Unwrap returns the underlying error.
func (e *DeviceError) Unwrap() error { return e.Err }

// ErrCommandFailed reports a TPM command that failed for a reason other than
// the blob: the device, the provider's own parent or session, a lockout, or
// retries that ran out.
var ErrCommandFailed = errors.New("tpm: a TPM command failed")

// CommandError is the error behind [ErrCommandFailed]. It wraps the go-tpm
// error, so errors.Is and errors.As still reach the TPM response code.
type CommandError struct {
	// Command names the TPM command, such as "TPM2_CreatePrimary".
	Command string
	// Err is the go-tpm or transport error.
	Err error
}

// Error implements error.
func (e *CommandError) Error() string {
	return ErrCommandFailed.Error() + ": " + e.Command + ": " + e.Err.Error()
}

// Is reports whether target is [ErrCommandFailed].
func (e *CommandError) Is(target error) bool { return target == ErrCommandFailed }

// Unwrap returns the underlying error.
func (e *CommandError) Unwrap() error { return e.Err }

// ErrKeySize reports a key Protect cannot seal: empty, or longer than the 128
// bytes of a TPM2B_SENSITIVE_DATA.
var ErrKeySize = errors.New("tpm: a sealed key must be 1 to 128 bytes")

// KeySizeError is the error behind [ErrKeySize].
type KeySizeError struct {
	// Len is the length of the key the caller passed.
	Len int
}

// Error implements error.
func (e *KeySizeError) Error() string {
	return ErrKeySize.Error() + ": got " + strconv.Itoa(e.Len)
}

// Is reports whether target is [ErrKeySize].
func (e *KeySizeError) Is(target error) bool { return target == ErrKeySize }

// ErrLockedMemory reports that the provider could not map or lock memory for
// a key transient. The error joins it with the system call's error.
var ErrLockedMemory = errors.New("tpm: no locked memory for a key transient")

// ErrClosed reports a call on a provider after Close.
var ErrClosed = errors.New("tpm: the provider is closed")

// authError refuses a blob this provider did not produce. It matches
// [enclave.ErrSealedAuthentication] and wraps the TPM error, if any.
type authError struct {
	reason string
	err    error
}

func (e *authError) Error() string {
	s := enclave.ErrSealedAuthentication.Error() + ": tpm: " + e.reason
	if e.err != nil {
		s += ": " + e.err.Error()
	}
	return s
}

func (e *authError) Is(target error) bool { return target == enclave.ErrSealedAuthentication }

func (e *authError) Unwrap() error { return e.err }

// command names a TPM command of the provider's sequences, for the result
// mapping and for the tests' fake device.
type command uint8

const (
	cmdCreatePrimary command = iota + 1
	cmdStartAuthSession
	cmdCreate
	cmdLoad
	cmdUnseal
	cmdFlushContext
)

func (c command) String() string {
	switch c {
	case cmdCreatePrimary:
		return "TPM2_CreatePrimary"
	case cmdStartAuthSession:
		return "TPM2_StartAuthSession"
	case cmdCreate:
		return "TPM2_Create"
	case cmdLoad:
		return "TPM2_Load"
	case cmdUnseal:
		return "TPM2_Unseal"
	case cmdFlushContext:
		return "TPM2_FlushContext"
	}
	return "command(" + strconv.Itoa(int(c)) + ")"
}

// outcome is what the provider does with a command's result.
type outcome uint8

const (
	outcomeSuccess outcome = iota
	// outcomeAuth refuses the blob: the error matches ErrSealedAuthentication.
	outcomeAuth
	// outcomeRetry sends the command again after a back-off.
	outcomeRetry
	// outcomeFail is the provider's own error.
	outcomeFail
)

// classify maps a command's result to an outcome, per the design's "Error
// mapping" table. A format-one code is compared with its handle, session or
// parameter number masked out, except where the table names a parameter.
func classify(cmd command, err error) outcome {
	if err == nil {
		return outcomeSuccess
	}
	var rc tpm2.TPMRC
	if !errors.As(err, &rc) {
		// A transport failure or a go-tpm local error.
		return outcomeFail
	}
	switch {
	case errors.Is(rc, tpm2.TPMRCRetry), errors.Is(rc, tpm2.TPMRCYielded), errors.Is(rc, tpm2.TPMRCTesting):
		return outcomeRetry
	case errors.Is(rc, tpm2.TPMRCLockout):
		return outcomeFail
	}
	switch cmd {
	case cmdLoad:
		if errors.Is(rc, tpm2.TPMRCIntegrity) {
			return outcomeAuth
		}
		var fmt1 tpm2.TPMFmt1Error
		if errors.As(rc, &fmt1) {
			if isParam, n := fmt1.Parameter(); isParam && (n == 1 || n == 2) {
				return outcomeAuth
			}
		}
	case cmdUnseal:
		if errors.Is(rc, tpm2.TPMRCBadAuth) || errors.Is(rc, tpm2.TPMRCAuthFail) || errors.Is(rc, tpm2.TPMRCPolicyFail) {
			return outcomeAuth
		}
	}
	return outcomeFail
}

// mapResult turns a command's final result into the error the provider
// returns: nil, an error matching ErrSealedAuthentication, or a
// [CommandError]. A retryable result that reaches it has run out of retries.
func mapResult(cmd command, err error) error {
	switch classify(cmd, err) {
	case outcomeSuccess:
		return nil
	case outcomeAuth:
		return &authError{reason: cmd.String() + " refused the blob", err: err}
	}
	return &CommandError{Command: cmd.String(), Err: err}
}

package macse

import (
	"errors"
	"strconv"
)

// The errors of the proposal's "Failure modes", named for the mechanism, not
// the contents. Match them with errors.Is: every failure the backend returns
// is a [*SecurityError] or a [*PlatformError] that matches one of them.
var (
	// ErrSecureEnclaveUnavailable means "not here": no Secure Enclave this
	// process can use (an Intel Mac without a T2 chip, a virtual machine, a
	// build without the binding, an identity missing). The probe and the
	// constructor return it; a lower-ranked backend stays selected.
	ErrSecureEnclaveUnavailable = errors.New("macse: secure enclave unavailable")

	// ErrSecureEnclaveOperation means "here, and this operation failed": the
	// key's access control refused the use, the Secure Enclave refused or
	// failed the call, or the call outlasted its bound.
	ErrSecureEnclaveOperation = errors.New("macse: secure enclave operation failed")

	// ErrInvalidSignInput is a digest that is not 32 bytes, or options that
	// do not name SHA-256, refused before any device call.
	ErrInvalidSignInput = errors.New("macse: sign input is not a SHA-256 digest")
)

// The steps a [*SecurityError] names, each one Security framework call (or,
// for OpVerify, the probe's own check of what the calls returned).
const (
	OpCreate   = "create"   // SecKeyCreateRandomKey with the Secure Enclave token
	OpPublic   = "public"   // SecKeyCopyPublicKey and its external representation
	OpSign     = "sign"     // SecKeyCreateSignature, ECDSA with SHA-256
	OpVerify   = "verify"   // the probe's check of the public key and signature
	OpIdentity = "identity" // the Managed Device Attestation identity lookup
)

// SecurityError is a failed step: the Security framework call it names
// returned an OSStatus, or what it returned did not hold. It matches
// [ErrSecureEnclaveUnavailable] when the step ran from the probe or the
// constructor, and [ErrSecureEnclaveOperation] when it ran from an operation
// on a usable backend.
type SecurityError struct {
	// Op is the step that failed: OpCreate, OpPublic, OpSign, OpVerify or
	// OpIdentity.
	Op string
	// Status is the OSStatus the call returned, 0 when the call succeeded
	// and its result failed the check.
	Status int32
	// Err is the cause beneath the status, such as context.DeadlineExceeded
	// or a malformed result; nil when the status says it all.
	Err error

	kind error // ErrSecureEnclaveUnavailable or ErrSecureEnclaveOperation
}

// unavailableError is a step that failed while finding out whether the
// Secure Enclave is usable.
func unavailableError(op string, status int32, cause error) *SecurityError {
	return &SecurityError{Op: op, Status: status, Err: cause, kind: ErrSecureEnclaveUnavailable}
}

func (e *SecurityError) Error() string {
	s := "macse: " + e.Op
	switch e.kind {
	case ErrSecureEnclaveUnavailable:
		s += ": secure enclave unavailable"
	case ErrSecureEnclaveOperation:
		s += ": secure enclave operation failed"
	}
	if e.Status != 0 {
		s += ": " + statusText(e.Status)
	}
	if e.Err != nil {
		s += ": " + e.Err.Error()
	}
	return s
}

// Is matches the class the error was made in.
func (e *SecurityError) Is(target error) bool { return e.kind != nil && target == e.kind }

// Unwrap returns the cause beneath the status.
func (e *SecurityError) Unwrap() error { return e.Err }

// PlatformError is a build without the Secure Enclave binding: a GOOS other
// than darwin, cgo off, or (in this slice) any build. It matches
// [ErrSecureEnclaveUnavailable] and has no cause.
type PlatformError struct {
	// Op is the step that found no binding: OpCreate, the probe's first.
	Op string
	// GOOS and GOARCH are the platform the module was built for.
	GOOS, GOARCH string
}

func (e *PlatformError) Error() string {
	return "macse: " + e.Op + ": secure enclave unavailable: no Security framework binding in this " +
		e.GOOS + "/" + e.GOARCH + " build"
}

// Is matches [ErrSecureEnclaveUnavailable].
func (e *PlatformError) Is(target error) bool { return target == ErrSecureEnclaveUnavailable }

// The OSStatus values the proposal's failure modes name, and the ones a
// Secure Enclave key's calls are documented to return (Security/SecBase.h).
var statusNames = map[int32]string{
	-4:     "errSecUnimplemented",
	-50:    "errSecParam",
	-108:   "errSecAllocate",
	-128:   "errSecUserCanceled",
	-25291: "errSecNotAvailable",
	-25293: "errSecAuthFailed",
	-25300: "errSecItemNotFound",
	-25308: "errSecInteractionNotAllowed",
	-34018: "errSecMissingEntitlement",
}

// statusText names an OSStatus, with its number: "errSecParam (-50)", or
// "OSStatus -1" for one the table does not know.
func statusText(status int32) string {
	n := strconv.FormatInt(int64(status), 10)
	if name, ok := statusNames[status]; ok {
		return name + " (" + n + ")"
	}
	return "OSStatus " + n
}

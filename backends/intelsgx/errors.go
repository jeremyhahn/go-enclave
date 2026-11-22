package intelsgx

import (
	"errors"
	"strconv"
)

// ErrSGXUnavailable reports that this process is not in an SGX enclave the
// backend can use: not under a library OS (no /dev/attestation), an
// attestation type other than DCAP, a debug enclave, an enclave that cannot
// quote, or a build for a platform other than linux/amd64. It means "not
// here". Every [SGXEnclaveError] matches it.
var ErrSGXUnavailable = errors.New("intelsgx: not in a usable SGX enclave")

// SGXEnclaveError is the error behind [ErrSGXUnavailable].
type SGXEnclaveError struct {
	// Op is the failing step: "platform" (a build for another GOOS or
	// GOARCH), "attestation_type", "report", "debug", "user_report_data",
	// "quote" or "random" (the probe's nonce).
	Op string
	// Cause is the refused call's *os.PathError, an [*AttestationTypeError]
	// with the value read, [ErrDebugEnclave], an [*SGXQuoteError] for a
	// quote that is not the one asked for, or nil for "platform".
	Cause error
}

// Error is [ErrSGXUnavailable]'s text, the step and the cause.
func (e *SGXEnclaveError) Error() string {
	msg := ErrSGXUnavailable.Error() + ": " + e.Op
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Is reports every SGXEnclaveError as [ErrSGXUnavailable].
func (e *SGXEnclaveError) Is(target error) bool { return target == ErrSGXUnavailable }

// Unwrap returns the cause.
func (e *SGXEnclaveError) Unwrap() error { return e.Cause }

// ErrSGXQuote reports that the enclave is usable but a quote request failed:
// the quote could not be produced, it does not carry the REPORT_DATA the
// backend wrote, or it is not a version 3 ECDSA quote. It means "here, and
// this request failed". Every [SGXQuoteError] matches it.
var ErrSGXQuote = errors.New("intelsgx: the SGX quote request failed")

// SGXQuoteError is the error behind [ErrSGXQuote].
type SGXQuoteError struct {
	// Op is the failing step: "user_report_data", "quote" (unreadable,
	// short or not version 3 ECDSA) or "report_data" (the quote's
	// REPORT_DATA is not what the backend wrote).
	Op string
	// Cause is the refused call's *os.PathError, a [*LayoutError], a
	// [*QuoteFormatError] or [ErrReportDataMismatch].
	Cause error
}

// Error is [ErrSGXQuote]'s text, the step and the cause.
func (e *SGXQuoteError) Error() string {
	msg := ErrSGXQuote.Error() + ": " + e.Op
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Is reports every SGXQuoteError as [ErrSGXQuote].
func (e *SGXQuoteError) Is(target error) bool { return target == ErrSGXQuote }

// Unwrap returns the cause.
func (e *SGXQuoteError) Unwrap() error { return e.Cause }

// ErrDebugEnclave reports an enclave whose own report sets ATTRIBUTES.DEBUG:
// its memory is readable from outside through EDBGRD, so the backend refuses
// it. It is the Cause of an [SGXEnclaveError] with Op "debug".
var ErrDebugEnclave = errors.New("intelsgx: the enclave is a debug enclave")

// ErrReportDataMismatch reports a quote whose REPORT_DATA is not the 64 bytes
// the backend wrote: another writer in the process raced it. It is the Cause
// of an [SGXQuoteError] with Op "report_data".
var ErrReportDataMismatch = errors.New("intelsgx: the quote's REPORT_DATA is not what was written")

// AttestationTypeError reports an attestation_type other than "dcap", such
// as "none" (Gramine without SGX, or attestation not enabled in the
// manifest). It is the Cause of an [SGXEnclaveError].
type AttestationTypeError struct {
	// Value is what attestation_type read, NUL and newline trimmed.
	Value string
}

// Error names the value read.
func (e *AttestationTypeError) Error() string {
	return "intelsgx: attestation type is not dcap: " + strconv.Quote(e.Value)
}

// LayoutError reports a structure shorter than its documented layout.
type LayoutError struct {
	// Structure is "report" (sgx_report_t) or "quote" (the DCAP quote v3
	// header and ISV enclave report body).
	Structure string
	// Want is the minimum length and Got the length read.
	Want, Got int
}

// Error names the structure and both lengths.
func (e *LayoutError) Error() string {
	return "intelsgx: " + e.Structure + " is " + strconv.Itoa(e.Got) + " bytes, want at least " + strconv.Itoa(e.Want)
}

// QuoteFormatError reports a quote that is not version 3 with an ECDSA
// P-256 attestation key (attestation key type 2).
type QuoteFormatError struct {
	// Version and KeyType are the quote header's fields.
	Version, KeyType uint16
}

// Error names the version and the attestation key type.
func (e *QuoteFormatError) Error() string {
	return "intelsgx: quote is version " + strconv.FormatUint(uint64(e.Version), 10) +
		" with attestation key type " + strconv.FormatUint(uint64(e.KeyType), 10) +
		", want version 3 with type 2 (ECDSA P-256)"
}

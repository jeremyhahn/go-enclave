package amdsev

import (
	"errors"
	"fmt"
)

var (
	// ErrSNPGuestUnavailable means "not here": this process does not run in
	// an SNP guest that can produce a report, so the backend cannot be built
	// and its probe fails. Every [*SNPGuestError] matches it; off Linux on
	// amd64 it is returned with no cause.
	ErrSNPGuestUnavailable = errors.New("amdsev: no SEV-SNP guest report interface on this host")

	// ErrSNPReport means "here, and this request failed": the guest is an
	// SNP guest, and one report request was refused or came back unusable.
	// Every [*SNPReportError] matches it.
	ErrSNPReport = errors.New("amdsev: SEV-SNP report request failed")

	// ErrProviderMismatch is the cause of an [*SNPGuestError] whose Op is
	// "provider": configfs-tsm is present but its provider is not sev_guest,
	// such as a TDX guest's tdx_guest.
	ErrProviderMismatch = errors.New("amdsev: configfs-tsm provider is not sev_guest")

	// ErrReportDataMismatch is the cause of an error whose Op is "report-data":
	// the report did not carry the nonce the request wrote.
	ErrReportDataMismatch = errors.New("amdsev: report does not carry the requested report data")

	// ErrGenerationMoved is the cause of an error whose Op is "generation":
	// another writer changed the configfs-tsm entry while its report was
	// read, so the report's provenance is unknown and it is discarded.
	ErrGenerationMoved = errors.New("amdsev: configfs-tsm generation moved during the request")
)

// SNPGuestError reports that the SNP guest report interface is missing or
// refuses this process. It matches [ErrSNPGuestUnavailable].
type SNPGuestError struct {
	// Op is the failing step: "mkdir", "provider", "generation", "inblob",
	// "outblob", "report-data" or "rmdir".
	Op string
	// Cause is the step's *os.PathError or *os.SyscallError (which wrap the
	// errno), or one of this package's cause sentinels.
	Cause error
}

func (e *SNPGuestError) Error() string {
	return fmt.Sprintf("amdsev: no usable SEV-SNP guest report interface: %s: %v", e.Op, e.Cause)
}

// Is reports whether target is [ErrSNPGuestUnavailable].
func (e *SNPGuestError) Is(target error) bool { return target == ErrSNPGuestUnavailable }

// Unwrap returns Cause.
func (e *SNPGuestError) Unwrap() error { return e.Cause }

// SNPReportError reports that one report request in an SNP guest failed. It
// matches [ErrSNPReport].
type SNPReportError struct {
	// Op is the failing step, as [SNPGuestError.Op] lists, or "size" for a
	// report that is not [ReportSize] bytes.
	Op string
	// Cause is the step's error.
	Cause error
}

func (e *SNPReportError) Error() string {
	return fmt.Sprintf("amdsev: SEV-SNP report request failed: %s: %v", e.Op, e.Cause)
}

// Is reports whether target is [ErrSNPReport].
func (e *SNPReportError) Is(target error) bool { return target == ErrSNPReport }

// Unwrap returns Cause.
func (e *SNPReportError) Unwrap() error { return e.Cause }

// ReportSizeError is the cause of a report that is not [ReportSize] bytes.
type ReportSizeError struct {
	// Got is the length read.
	Got int
}

func (e *ReportSizeError) Error() string {
	return fmt.Sprintf("amdsev: report is %d bytes, want %d", e.Got, ReportSize)
}

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
	// Op is the failing step, as [SNPGuestError.Op] lists; "outblob" with a
	// [*ReportSizeError] cause for a report that is not [ReportSize] bytes.
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

// FirmwareError is the cause of an [*SNPReportError] whose Op is
// "derived-key": the guest request reached the sev-guest driver and the
// firmware, the hypervisor or the response refused it.
type FirmwareError struct {
	// FWError is the firmware's error word, the low half of exitinfo2: an
	// SEV firmware status code, or all ones when the request never reached
	// the firmware.
	FWError uint32
	// VMMError is the hypervisor's error word, the high half of exitinfo2:
	// 1 for a buffer too short, 2 for a host too busy to take the request.
	VMMError uint32
	// Status is the response's STATUS word when the ioctl succeeded and the
	// firmware refused the key request, such as 0x16 for an invalid
	// parameter.
	Status uint32
	// Errno is the ioctl's *os.SyscallError, nil when Status refused.
	Errno error
}

func (e *FirmwareError) Error() string {
	if e.Errno == nil {
		return fmt.Sprintf("amdsev: firmware refused the key request: status %#x", e.Status)
	}
	return fmt.Sprintf("amdsev: guest request refused: firmware error %#x, hypervisor error %#x: %v",
		e.FWError, e.VMMError, e.Errno)
}

// Unwrap returns Errno.
func (e *FirmwareError) Unwrap() error { return e.Errno }

// KeySizeError reports a key destination that is not 32 bytes, refused
// before any request.
type KeySizeError struct {
	// Got is the destination's length.
	Got int
}

func (e *KeySizeError) Error() string {
	return fmt.Sprintf("amdsev: key destination is %d bytes, want %d", e.Got, derivedKeySize)
}

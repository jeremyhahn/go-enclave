package amdsev

import (
	"errors"
	"strconv"
)

// ErrSNPGuestUnavailable reports that this process could not prove it runs
// inside an SEV-SNP guest: the guest device is absent or refuses the process,
// its report request failed, and no configfs-tsm report entry names the
// sev_guest provider. A host, a plain VM and an SEV or SEV-ES guest without
// SNP all end here. Every [GuestError] matches it.
var ErrSNPGuestUnavailable = errors.New("amdsev: not an SEV-SNP guest")

// ErrWrongProvider reports a configfs-tsm report entry whose provider is not
// sev_guest, such as tdx_guest. It is the Cause of a [GuestError]; every
// [ProviderError] matches it.
var ErrWrongProvider = errors.New("amdsev: the configfs-tsm provider is not sev_guest")

// ErrReportRefused reports an SNP_GET_REPORT request the ioctl accepted but
// whose response is not a report: a non-zero firmware status or a report of
// the wrong size. It is the Cause of a [GuestError]; every [ReportError]
// matches it.
var ErrReportRefused = errors.New("amdsev: the SEV-SNP firmware refused the report request")

// GuestError is the error behind [ErrSNPGuestUnavailable]. It names the step
// that failed and wraps the OS error. When the guest device fails, detection
// also tries configfs-tsm, and Next is that step's GuestError.
type GuestError struct {
	// Path is the device or configfs path the step used.
	Path string
	// Op is the failed step: "platform" (not Linux), "open" and "report"
	// for /dev/sev-guest; "mkdir", "provider" and "rmdir" for configfs-tsm.
	Op string
	// Cause is the refused call's *os.PathError or *os.SyscallError, a
	// [*ProviderError], a [*ReportError], or errors.ErrUnsupported.
	Cause error
	// Next is the configfs-tsm step's error after the device failed, or nil.
	Next error
}

// Error is [ErrSNPGuestUnavailable]'s text, the step, the path and the
// cause, followed by Next's text.
func (e *GuestError) Error() string {
	msg := ErrSNPGuestUnavailable.Error() + ": " + e.Op
	if e.Path != "" {
		msg += " " + strconv.Quote(e.Path)
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	if e.Next != nil {
		msg += "; " + e.Next.Error()
	}
	return msg
}

// Is reports every GuestError as [ErrSNPGuestUnavailable].
func (e *GuestError) Is(target error) bool { return target == ErrSNPGuestUnavailable }

// Unwrap returns the cause and, if set, Next.
func (e *GuestError) Unwrap() []error {
	errs := make([]error, 0, 2)
	if e.Cause != nil {
		errs = append(errs, e.Cause)
	}
	if e.Next != nil {
		errs = append(errs, e.Next)
	}
	return errs
}

// ProviderError is the error behind [ErrWrongProvider].
type ProviderError struct {
	// Provider is the provider the entry named.
	Provider string
}

// Error is [ErrWrongProvider]'s text with the quoted provider.
func (e *ProviderError) Error() string {
	return ErrWrongProvider.Error() + ": " + strconv.Quote(e.Provider)
}

// Is reports every ProviderError as [ErrWrongProvider].
func (e *ProviderError) Is(target error) bool { return target == ErrWrongProvider }

// ReportError is the error behind [ErrReportRefused].
type ReportError struct {
	// Status is the MSG_REPORT_RSP status; 0 is success.
	Status uint32
	// Size is the report size the response claimed.
	Size uint32
}

// Error is [ErrReportRefused]'s text with the status and the size.
func (e *ReportError) Error() string {
	return ErrReportRefused.Error() + ": status " + strconv.FormatUint(uint64(e.Status), 10) +
		", report size " + strconv.FormatUint(uint64(e.Size), 10)
}

// Is reports every ReportError as [ErrReportRefused].
func (e *ReportError) Is(target error) bool { return target == ErrReportRefused }

package inteltdx

import "errors"

// The errors are named for the mechanism that failed (the guest device, the
// report interface, a measurement register), not for what it carried, as
// docs/backends/intel-tdx.md "Failure modes" proposes. Each typed error
// names the failing step in Op and wraps the refused call's error in Cause.

// ErrGuestDeviceUnavailable reports that the TDX guest device refused the
// backend: /dev/tdx_guest is absent (not a TD, or no driver), refuses the
// process, or TDX_CMD_GET_REPORT0 failed; or the build is not linux/amd64.
// Every [GuestDeviceError] matches it.
var ErrGuestDeviceUnavailable = errors.New("inteltdx: the TDX guest device is unavailable")

// GuestDeviceError is the error behind [ErrGuestDeviceUnavailable].
type GuestDeviceError struct {
	// Op is the refused step: "open", "get-report" or "close"; off
	// linux/amd64 it is "platform" and the GOOS/GOARCH built for.
	Op string
	// Cause is the refused call's *fs.PathError or *os.SyscallError, which
	// wraps the errno; nil for a platform refusal.
	Cause error
}

// Error is [ErrGuestDeviceUnavailable]'s text, the step and the cause.
func (e *GuestDeviceError) Error() string {
	return withCause(ErrGuestDeviceUnavailable.Error()+": "+e.Op, e.Cause)
}

// Is reports every GuestDeviceError as [ErrGuestDeviceUnavailable].
func (e *GuestDeviceError) Is(target error) bool { return target == ErrGuestDeviceUnavailable }

// Unwrap returns the cause.
func (e *GuestDeviceError) Unwrap() error { return e.Cause }

// ErrDebugTD reports a TD launched with ATTRIBUTES.DEBUG set: the host can
// read its memory, so the backend refuses it.
var ErrDebugTD = errors.New("inteltdx: the TD runs with ATTRIBUTES.DEBUG set; the host can read its memory")

// ErrTSMReportUnavailable reports that the configfs-tsm report interface
// refused the backend: /sys/kernel/config/tsm/report is absent (a kernel
// before 6.7, no CONFIG_TSM_REPORTS, configfs not mounted), its provider is
// not tdx_guest, or a mkdir, inblob or outblob step failed (EIO: no quote
// from the host; EFBIG; EACCES). Every [TSMReportError] matches it.
var ErrTSMReportUnavailable = errors.New("inteltdx: the configfs-tsm report interface is unavailable")

// ErrTSMReportConflict is a [TSMReportError]'s Cause when the report's
// generation moved past this call's own write: another writer shared the
// report directory.
var ErrTSMReportConflict = errors.New("inteltdx: the report's generation moved past this call's write")

// TSMReportError is the error behind [ErrTSMReportUnavailable].
type TSMReportError struct {
	// Op is the refused step: "stat", "mkdir", "provider", "inblob",
	// "outblob", "generation" or "rmdir".
	Op string
	// Cause is the refused call's *fs.PathError, which wraps the errno, or
	// [ErrTSMReportConflict], or the provider mismatch.
	Cause error
}

// Error is [ErrTSMReportUnavailable]'s text, the step and the cause.
func (e *TSMReportError) Error() string {
	return withCause(ErrTSMReportUnavailable.Error()+": "+e.Op, e.Cause)
}

// Is reports every TSMReportError as [ErrTSMReportUnavailable].
func (e *TSMReportError) Is(target error) bool { return target == ErrTSMReportUnavailable }

// Unwrap returns the cause.
func (e *TSMReportError) Unwrap() error { return e.Cause }

// ErrMeasurementRegisterUnavailable reports that a measurement register under
// /sys/devices/virtual/misc/tdx_guest/measurements is absent (a kernel before
// 6.16) or refused a read or write. Every [MeasurementRegisterError] matches
// it.
var ErrMeasurementRegisterUnavailable = errors.New("inteltdx: the measurement register is unavailable")

// MeasurementRegisterError is the error behind
// [ErrMeasurementRegisterUnavailable].
type MeasurementRegisterError struct {
	// Register is the register's file name, such as "rtmr3:sha384".
	Register string
	// Cause is the refused call's *fs.PathError, which wraps the errno.
	Cause error
}

// Error is [ErrMeasurementRegisterUnavailable]'s text, the register and the
// cause.
func (e *MeasurementRegisterError) Error() string {
	return withCause(ErrMeasurementRegisterUnavailable.Error()+": "+e.Register, e.Cause)
}

// Is reports every MeasurementRegisterError as
// [ErrMeasurementRegisterUnavailable].
func (e *MeasurementRegisterError) Is(target error) bool {
	return target == ErrMeasurementRegisterUnavailable
}

// Unwrap returns the cause.
func (e *MeasurementRegisterError) Unwrap() error { return e.Cause }

// withCause appends the cause's text to msg, when there is a cause.
func withCause(msg string, cause error) string {
	if cause != nil {
		msg += ": " + cause.Error()
	}
	return msg
}

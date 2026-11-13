package confidentialvm

import (
	"errors"
	"fmt"
)

// The errors are named for the mechanism that failed, the configfs-tsm report
// interface or the SNP derived key, as docs/backends/confidential-vm.md "Failure modes" proposes.

// ErrTSMReportUnavailable reports that the configfs-tsm report interface
// refused: it is absent (not a confidential VM, configfs not mounted, not
// linux/amd64), not permitted, its provider is neither sev_guest nor
// tdx_guest, or the platform refused the request. A *TSMReportError matches
// it with errors.Is.
var ErrTSMReportUnavailable = errors.New("confidentialvm: configfs-tsm report unavailable")

// ErrTSMReportConflict reports that another writer moved a report entry's
// generation while this call used it, so the report's provenance is unknown
// and it is discarded. It is the Cause of a *TSMReportError.
var ErrTSMReportConflict = errors.New("confidentialvm: configfs-tsm report entry written by another writer")

// TSMReportError is a refused step of a configfs-tsm report request. It
// matches [ErrTSMReportUnavailable], and unwraps to Cause.
type TSMReportError struct {
	// Op is the refused step: "stat", "mkdir", "provider", "inblob",
	// "outblob", "generation" or "rmdir".
	Op string
	// Cause is the refused call's error (a *fs.PathError wrapping the errno),
	// [ErrTSMReportConflict], or the provider or parse failure. It is nil off
	// linux/amd64.
	Cause error
}

func (e *TSMReportError) Error() string {
	msg := "confidentialvm: configfs-tsm report"
	if e.Op != "" {
		msg += " " + e.Op
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Is matches [ErrTSMReportUnavailable].
func (e *TSMReportError) Is(target error) bool { return target == ErrTSMReportUnavailable }

// Unwrap returns Cause.
func (e *TSMReportError) Unwrap() error { return e.Cause }

// ErrDerivedKeyUnavailable is matched by every *DerivedKeyError: the SNP
// derived key cannot be had here. That is no /dev/sev-guest (a TDX guest, or
// no confidential VM), a refused device, or a refused SNP_GET_DERIVED_KEY.
var ErrDerivedKeyUnavailable = errors.New("confidentialvm: SNP derived key unavailable")

// DerivedKeyError is a refused step of the SNP derived-key KeyProtector. It
// matches [ErrDerivedKeyUnavailable], never enclave.ErrSealedAuthentication,
// and unwraps to Cause.
type DerivedKeyError struct {
	// Op is the refused step: "open", "report", "derived-key" or "memory".
	Op string
	// Cause is the refused call's error: a *fs.PathError for "open", the
	// *TSMReportError or the short report for "report", a *FirmwareError for
	// "derived-key". It is nil off linux/amd64.
	Cause error
}

func (e *DerivedKeyError) Error() string {
	msg := "confidentialvm: SNP derived key"
	if e.Op != "" {
		msg += " " + e.Op
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Is matches [ErrDerivedKeyUnavailable].
func (e *DerivedKeyError) Is(target error) bool { return target == ErrDerivedKeyUnavailable }

// Unwrap returns Cause.
func (e *DerivedKeyError) Unwrap() error { return e.Cause }

// FirmwareError is a refused SNP_GET_DERIVED_KEY: the ioctl failed, with the
// firmware's and the hypervisor's error words, or it succeeded and the
// response's STATUS refused the request.
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
		return fmt.Sprintf("firmware refused the key request: status %#x", e.Status)
	}
	return fmt.Sprintf("guest request refused: firmware error %#x, hypervisor error %#x: %v",
		e.FWError, e.VMMError, e.Errno)
}

// Unwrap returns Errno.
func (e *FirmwareError) Unwrap() error { return e.Errno }

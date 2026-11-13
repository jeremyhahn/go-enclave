package confidentialvm

import "errors"

// The errors are named for the mechanism that failed, the configfs-tsm report
// interface, as docs/backends/confidential-vm.md "Failure modes" proposes.

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

package confidentialvm

import (
	"errors"
	"io/fs"
	"testing"
)

func TestTSMReportError_MatchesUnavailableAndUnwrapsItsCause(t *testing.T) {
	cause := &fs.PathError{Op: "open", Path: "outblob", Err: fs.ErrPermission}
	err := error(&TSMReportError{Op: "outblob", Cause: cause})
	if !errors.Is(err, ErrTSMReportUnavailable) || !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("%v does not match ErrTSMReportUnavailable and its cause", err)
	}
	if errors.Is(err, ErrTSMReportConflict) {
		t.Fatalf("%v matches ErrTSMReportConflict", err)
	}
	if got, want := err.Error(), "confidentialvm: configfs-tsm report outblob: open outblob: permission denied"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	conflict := &TSMReportError{Op: "generation", Cause: ErrTSMReportConflict}
	if !errors.Is(conflict, ErrTSMReportConflict) {
		t.Fatalf("%v does not match ErrTSMReportConflict", conflict)
	}
	bare := &TSMReportError{}
	if bare.Error() != "confidentialvm: configfs-tsm report" || bare.Unwrap() != nil || !errors.Is(bare, ErrTSMReportUnavailable) {
		t.Fatalf("bare error = %q, unwrap %v", bare.Error(), bare.Unwrap())
	}
}

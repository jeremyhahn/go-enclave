package amdsev

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

func TestErrorsMatchTheirSentinels(t *testing.T) {
	cause := &os.PathError{Op: "mkdir", Path: "/sys/kernel/config/tsm/report/x", Err: syscall.ENOENT}
	var guest error = &SNPGuestError{Op: "mkdir", Cause: cause}
	if !errors.Is(guest, ErrSNPGuestUnavailable) || errors.Is(guest, ErrSNPReport) {
		t.Errorf("SNPGuestError: Is(ErrSNPGuestUnavailable) must hold and Is(ErrSNPReport) must not")
	}
	if !errors.Is(guest, fs.ErrNotExist) || !errors.Is(guest, syscall.ENOENT) {
		t.Errorf("SNPGuestError does not unwrap to its errno: %v", guest)
	}
	var report error = &SNPReportError{Op: "generation", Cause: ErrGenerationMoved}
	if !errors.Is(report, ErrSNPReport) || errors.Is(report, ErrSNPGuestUnavailable) {
		t.Errorf("SNPReportError: Is(ErrSNPReport) must hold and Is(ErrSNPGuestUnavailable) must not")
	}
	if !errors.Is(report, ErrGenerationMoved) {
		t.Errorf("SNPReportError does not unwrap to its cause: %v", report)
	}
	for _, err := range []error{guest, report, &ReportSizeError{Got: 1}} {
		if err.Error() == "" {
			t.Errorf("%T has an empty message", err)
		}
	}
}

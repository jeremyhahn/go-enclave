package inteltdx

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"testing"
)

func TestGuestDeviceError(t *testing.T) {
	cause := &fs.PathError{Op: "open", Path: guestDevice, Err: syscall.ENOENT}
	var err error = &GuestDeviceError{Op: "open", Cause: cause}
	if !errors.Is(err, ErrGuestDeviceUnavailable) {
		t.Fatal("GuestDeviceError does not match ErrGuestDeviceUnavailable")
	}
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatal("GuestDeviceError does not unwrap to its errno")
	}
	if errors.Is(err, ErrTSMReportUnavailable) {
		t.Fatal("GuestDeviceError matches ErrTSMReportUnavailable")
	}
	want := "inteltdx: the TDX guest device is unavailable: open: open /dev/tdx_guest: no such file or directory"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	noCause := &GuestDeviceError{Op: "platform darwin/amd64"}
	if got, want := noCause.Error(), "inteltdx: the TDX guest device is unavailable: platform darwin/amd64"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if noCause.Unwrap() != nil {
		t.Fatal("a platform refusal has a cause")
	}
}

func TestTSMReportError(t *testing.T) {
	var err error = &TSMReportError{Op: "generation", Cause: ErrTSMReportConflict}
	if !errors.Is(err, ErrTSMReportUnavailable) || !errors.Is(err, ErrTSMReportConflict) {
		t.Fatal("TSMReportError does not match its sentinel and its cause")
	}
	if errors.Is(err, ErrGuestDeviceUnavailable) {
		t.Fatal("TSMReportError matches ErrGuestDeviceUnavailable")
	}
	want := "inteltdx: the configfs-tsm report interface is unavailable: generation: inteltdx: the report's generation moved past this call's write"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	eio := &TSMReportError{Op: "outblob", Cause: &fs.PathError{Op: "read", Path: "outblob", Err: syscall.EIO}}
	if !errors.Is(eio, syscall.EIO) {
		t.Fatal("TSMReportError does not unwrap to its errno")
	}
}

func TestMeasurementRegisterError(t *testing.T) {
	cause := &os.SyscallError{Syscall: "write", Err: syscall.EINVAL}
	var err error = &MeasurementRegisterError{Register: "rtmr3:sha384", Cause: cause}
	if !errors.Is(err, ErrMeasurementRegisterUnavailable) || !errors.Is(err, syscall.EINVAL) {
		t.Fatal("MeasurementRegisterError does not match its sentinel and its errno")
	}
	want := "inteltdx: the measurement register is unavailable: rtmr3:sha384: write: invalid argument"
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	var target *MeasurementRegisterError
	if !errors.As(err, &target) || target.Register != "rtmr3:sha384" {
		t.Fatal("errors.As does not reach the MeasurementRegisterError")
	}
}

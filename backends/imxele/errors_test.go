package imxele

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestTEEDeviceErrorMatchesAndUnwraps(t *testing.T) {
	err := error(&TEEDeviceError{Path: "/dev/tee0", Op: "open", Cause: os.NewSyscallError("open", syscall.ENOENT)})
	if !errors.Is(err, ErrTEEDeviceUnavailable) {
		t.Errorf("errors.Is(%v, ErrTEEDeviceUnavailable) = false", err)
	}
	if !errors.Is(err, syscall.ENOENT) {
		t.Errorf("errors.Is(%v, ENOENT) = false; the errno must stay reachable", err)
	}
	if errors.Is(err, ErrTEESessionUnavailable) {
		t.Errorf("a device error matches ErrTEESessionUnavailable")
	}
	if got := err.Error(); !strings.Contains(got, "/dev/tee0") || !strings.Contains(got, "open") {
		t.Errorf("Error() = %q, want the path and the step", got)
	}
	noCause := &TEEDeviceError{Path: "/dev/tee0", Op: "platform"}
	if !errors.Is(noCause, ErrTEEDeviceUnavailable) || noCause.Unwrap() != nil {
		t.Errorf("a causeless device error must match ErrTEEDeviceUnavailable and unwrap to nil")
	}
	if got := noCause.Error(); !strings.Contains(got, "platform") {
		t.Errorf("Error() = %q, want the step", got)
	}
}

func TestTEESessionError(t *testing.T) {
	err := error(&TEESessionError{UUID: "00000000-0000-0000-0000-000000000000", Code: 0xffff0008, Origin: 3})
	if !errors.Is(err, ErrTEESessionUnavailable) || errors.Is(err, ErrTEEDeviceUnavailable) {
		t.Errorf("session error matching is wrong: %v", err)
	}
	if got := err.Error(); !strings.Contains(got, "0xffff0008") {
		t.Errorf("Error() = %q, want the result code", got)
	}
	wrapped := &TEESessionError{Cause: errTAUnpublished}
	if !errors.Is(wrapped, errTAUnpublished) {
		t.Errorf("the session error's cause is not reachable")
	}
}

func TestABIVersionError(t *testing.T) {
	err := error(&ABIVersionError{Got: 2, Want: 1})
	if !errors.Is(err, ErrABIVersionUnsupported) {
		t.Errorf("errors.Is(%v, ErrABIVersionUnsupported) = false", err)
	}
	if got := err.Error(); !strings.Contains(got, "2") || !strings.Contains(got, "1") {
		t.Errorf("Error() = %q, want both versions", got)
	}
}

func TestTEECommandError(t *testing.T) {
	err := error(&TEECommandError{Command: 7, Code: 0xffff000c, Origin: 4})
	if !errors.Is(err, ErrTEECommandFailed) {
		t.Errorf("errors.Is(%v, ErrTEECommandFailed) = false", err)
	}
	timeout := &TEECommandError{Command: 7, Cause: context.DeadlineExceeded}
	if !errors.Is(timeout, context.DeadlineExceeded) || !errors.Is(timeout, ErrTEECommandFailed) {
		t.Errorf("a timed-out command must match both its cause and ErrTEECommandFailed")
	}
	if got := timeout.Error(); !strings.Contains(got, "deadline") {
		t.Errorf("Error() = %q, want the cause", got)
	}
}

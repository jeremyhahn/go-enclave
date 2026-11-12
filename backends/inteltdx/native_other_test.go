//go:build !(linux && amd64)

package inteltdx

import (
	"errors"
	"testing"
)

// Off linux/amd64 the native interface refuses as the probe does: the guest
// device is unavailable for the platform, and a register refusal names the
// register over that platform refusal.
func TestNativeStubRefuses(t *testing.T) {
	b := &Backend{}
	report, err := b.Report([reportDataSize]byte{})
	var ge *GuestDeviceError
	if !errors.As(err, &ge) || ge.Cause != nil || report != nil {
		t.Fatalf("Report() = %x, %v; want a platform GuestDeviceError", report, err)
	}
	_, err = b.Measurements()
	var me *MeasurementRegisterError
	if !errors.As(err, &me) || me.Register != "mrtd:sha384" || !errors.Is(err, ErrGuestDeviceUnavailable) {
		t.Fatalf("Measurements() = %v, want a MeasurementRegisterError naming mrtd:sha384 over the platform refusal", err)
	}
	err = b.ExtendRTMR(3, [registerSize]byte{})
	if !errors.As(err, &me) || me.Register != "rtmr3:sha384" || !errors.Is(err, ErrGuestDeviceUnavailable) {
		t.Fatalf("ExtendRTMR(3) = %v, want a MeasurementRegisterError naming rtmr3:sha384 over the platform refusal", err)
	}
}

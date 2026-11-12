package inteltdx

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// skipWithRegisters skips where the measurements directory exists: inside a
// TD the register paths are the integration target's.
func skipWithRegisters(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(measurementsDir); err == nil {
		t.Skip(measurementsDir + " is present: the register paths are the integration target's")
	}
}

// wantRegisterENOENT checks a refusal names the register and wraps the
// *fs.PathError carrying ENOENT.
func wantRegisterENOENT(t *testing.T, what string, err error, register string) {
	t.Helper()
	var me *MeasurementRegisterError
	if !errors.As(err, &me) || me.Register != register {
		t.Fatalf("%s = %v, want a MeasurementRegisterError naming %s", what, err, register)
	}
	var pe *fs.PathError
	if !errors.As(err, &pe) {
		t.Fatalf("%s = %v, want an *fs.PathError under it", what, err)
	}
	if !errors.Is(err, ErrMeasurementRegisterUnavailable) || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("%s = %v, want ErrMeasurementRegisterUnavailable wrapping ENOENT", what, err)
	}
}

func TestReportRefusesOffTD(t *testing.T) {
	skipInTD(t)
	report, err := (&Backend{}).Report([reportDataSize]byte{1})
	var ge *GuestDeviceError
	if !errors.As(err, &ge) || ge.Op != "open" || report != nil {
		t.Fatalf("Report() = %x, %v; want a GuestDeviceError at open", report, err)
	}
	if !errors.Is(err, ErrGuestDeviceUnavailable) || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("Report() = %v, want ErrGuestDeviceUnavailable wrapping ENOENT", err)
	}
}

func TestMeasurementsRefusesOffTD(t *testing.T) {
	skipWithRegisters(t)
	_, err := (&Backend{}).Measurements()
	wantRegisterENOENT(t, "Measurements()", err, "mrtd:sha384")
}

func TestExtendRTMRRefusesOffTD(t *testing.T) {
	skipWithRegisters(t)
	err := (&Backend{}).ExtendRTMR(3, [registerSize]byte{1})
	wantRegisterENOENT(t, "ExtendRTMR(3)", err, "rtmr3:sha384")
}

// enclave.As reaches the native interface: a *Backend held as a seam value
// is assignable to a *Backend target.
func TestNativeThroughAs(t *testing.T) {
	skipInTD(t)
	skipWithRegisters(t)
	var p enclave.Prober = &Backend{}
	var tdx *Backend
	if !enclave.As(p, &tdx) || tdx == nil {
		t.Fatal("enclave.As(backend, *Backend) = false")
	}
	if _, err := tdx.Report([reportDataSize]byte{}); !errors.Is(err, ErrGuestDeviceUnavailable) {
		t.Fatalf("Report() through As = %v, want ErrGuestDeviceUnavailable", err)
	}
	if _, err := tdx.Measurements(); !errors.Is(err, ErrMeasurementRegisterUnavailable) {
		t.Fatalf("Measurements() through As = %v, want ErrMeasurementRegisterUnavailable", err)
	}
	if err := tdx.ExtendRTMR(0, [registerSize]byte{}); !errors.Is(err, ErrMeasurementRegisterUnavailable) {
		t.Fatalf("ExtendRTMR() through As = %v, want ErrMeasurementRegisterUnavailable", err)
	}
}

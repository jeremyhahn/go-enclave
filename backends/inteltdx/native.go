package inteltdx

import (
	"errors"
	"fmt"
)

// The native interface, reached through enclave.As (a *Backend is assignable
// to a *Backend target, so the backend needs no As method): Report returns the
// raw TDREPORT, Measurements reads the measurement registers and ExtendRTMR
// extends one. The seam models none of them (docs/backends/intel-tdx.md,
// "Shape proposed", Native interface).
//
// Q8 takes the recommended option, native only: the backend never extends an
// RTMR on its own. An extension cannot be undone for the TD's life, so it is
// a process-wide decision for main, made through ExtendRTMR.

const (
	// measurementsDir holds the measurement registers (Linux 6.16).
	measurementsDir = "/sys/devices/virtual/misc/tdx_guest/measurements"
	// registerSize is a register's size: a SHA-384 digest.
	registerSize = 48
	// rtmrCount is the number of runtime measurement registers.
	rtmrCount = 4
	// rtmrFirst is the index of rtmr0:sha384 in registerNames.
	rtmrFirst = 4
)

// registerNames are the register files under measurementsDir, in the order
// Measurements reads them and [Measurements.set] stores them.
var registerNames = [rtmrFirst + rtmrCount]string{
	"mrtd:sha384", "mrconfigid", "mrowner", "mrownerconfig",
	"rtmr0:sha384", "rtmr1:sha384", "rtmr2:sha384", "rtmr3:sha384",
}

// ErrRTMRIndex reports an RTMR index outside 0 to 3; ExtendRTMR refuses it
// before it opens any file.
var ErrRTMRIndex = errors.New("inteltdx: an RTMR index is 0 to 3")

// errRegisterSize is a [MeasurementRegisterError]'s Cause when a register
// read returned other than 48 bytes.
var errRegisterSize = errors.New("register read is not 48 bytes")

// Measurements are the TD's measurement registers as the kernel reports them.
type Measurements struct {
	// MRTD measures the TD's initial contents (mrtd:sha384).
	MRTD [registerSize]byte
	// MRConfigID is the VMM-supplied configuration ID (mrconfigid).
	MRConfigID [registerSize]byte
	// MROwner identifies the TD's owner (mrowner).
	MROwner [registerSize]byte
	// MROwnerConfig is the owner-defined configuration (mrownerconfig).
	MROwnerConfig [registerSize]byte
	// RTMR are the runtime measurement registers, rtmr0:sha384 to
	// rtmr3:sha384.
	RTMR [rtmrCount][registerSize]byte
}

// set stores value as the register registerNames[i] names.
func (m *Measurements) set(i int, value [registerSize]byte) {
	switch i {
	case 0:
		m.MRTD = value
	case 1:
		m.MRConfigID = value
	case 2:
		m.MROwner = value
	case 3:
		m.MROwnerConfig = value
	default:
		m.RTMR[i-rtmrFirst] = value
	}
}

// rtmrName is the register file of RTMR index, or ErrRTMRIndex.
func rtmrName(index int) (string, error) {
	if index < 0 || index >= rtmrCount {
		return "", fmt.Errorf("%w: %d", ErrRTMRIndex, index)
	}
	return registerNames[rtmrFirst+index], nil
}

// parseRegister takes a register read: exactly 48 bytes, or a refusal naming
// the register.
func parseRegister(name string, b []byte) ([registerSize]byte, error) {
	var value [registerSize]byte
	if len(b) != registerSize {
		return value, &MeasurementRegisterError{
			Register: name,
			Cause:    fmt.Errorf("%w: %d bytes", errRegisterSize, len(b)),
		}
	}
	copy(value[:], b)
	return value, nil
}

// Report returns the raw 1024-byte TDREPORT for reportData, from
// TDX_CMD_GET_REPORT0 on the guest device. A refusal is a
// [*GuestDeviceError].
func (b *Backend) Report(reportData [reportDataSize]byte) ([]byte, error) {
	return report(reportData)
}

// Measurements reads every measurement register. The first register refused
// is a [*MeasurementRegisterError] naming it and wrapping the *fs.PathError,
// or the size refusal when a read is not 48 bytes.
func (b *Backend) Measurements() (Measurements, error) {
	var m Measurements
	for i, name := range registerNames {
		raw, err := readRegister(name)
		if err != nil {
			return Measurements{}, err
		}
		value, err := parseRegister(name, raw)
		if err != nil {
			return Measurements{}, err
		}
		m.set(i, value)
	}
	return m, nil
}

// ExtendRTMR extends RTMR index (0 to 3) with digest: a 48-byte write at
// offset 0 of rtmrN:sha384, which the kernel turns into TDG.MR.RTMR.EXTEND.
// The extension lasts for the TD's life. An index outside 0 to 3 is
// [ErrRTMRIndex], refused before any open; a refused write is a
// [*MeasurementRegisterError] wrapping the *fs.PathError.
func (b *Backend) ExtendRTMR(index int, digest [registerSize]byte) error {
	name, err := rtmrName(index)
	if err != nil {
		return err
	}
	return writeRegister(name, digest)
}

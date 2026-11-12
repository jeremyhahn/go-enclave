package inteltdx

import (
	"bytes"
	"errors"
	"testing"
)

// The register files, in the order Measurements reads them, as the kernel
// names them under the measurements directory.
func TestRegisterNames(t *testing.T) {
	want := []string{
		"mrtd:sha384", "mrconfigid", "mrowner", "mrownerconfig",
		"rtmr0:sha384", "rtmr1:sha384", "rtmr2:sha384", "rtmr3:sha384",
	}
	if len(registerNames) != len(want) {
		t.Fatalf("registerNames has %d names, want %d", len(registerNames), len(want))
	}
	for i, name := range want {
		if registerNames[i] != name {
			t.Errorf("registerNames[%d] = %q, want %q", i, registerNames[i], name)
		}
	}
	for i := range rtmrCount {
		name, err := rtmrName(i)
		if err != nil || name != want[4+i] {
			t.Errorf("rtmrName(%d) = %q, %v; want %q", i, name, err, want[4+i])
		}
	}
}

// An index outside 0..3 is refused with ErrRTMRIndex before any open: the
// error carries no register and no path, so no file was touched.
func TestRTMRIndexRefused(t *testing.T) {
	for _, index := range []int{-1, 4} {
		if name, err := rtmrName(index); !errors.Is(err, ErrRTMRIndex) || name != "" {
			t.Errorf("rtmrName(%d) = %q, %v; want ErrRTMRIndex", index, name, err)
		}
		err := (&Backend{}).ExtendRTMR(index, [registerSize]byte{})
		if !errors.Is(err, ErrRTMRIndex) {
			t.Errorf("ExtendRTMR(%d) = %v, want ErrRTMRIndex", index, err)
		}
		var me *MeasurementRegisterError
		if errors.As(err, &me) {
			t.Errorf("ExtendRTMR(%d) = %v, reached a register", index, err)
		}
	}
}

// The parser takes exactly 48 bytes, a SHA-384 digest; a short or long read
// is refused naming the register.
func TestParseRegister(t *testing.T) {
	full := bytes.Repeat([]byte{0xa5}, registerSize)
	got, err := parseRegister("mrtd:sha384", full)
	if err != nil || !bytes.Equal(got[:], full) {
		t.Fatalf("parseRegister(48 bytes) = %x, %v; want the bytes", got, err)
	}
	for _, n := range []int{registerSize - 1, registerSize + 1} {
		_, err := parseRegister("rtmr2:sha384", bytes.Repeat([]byte{1}, n))
		var me *MeasurementRegisterError
		if !errors.As(err, &me) || me.Register != "rtmr2:sha384" {
			t.Errorf("parseRegister(%d bytes) = %v, want a MeasurementRegisterError naming rtmr2:sha384", n, err)
		}
		if !errors.Is(err, ErrMeasurementRegisterUnavailable) || !errors.Is(err, errRegisterSize) {
			t.Errorf("parseRegister(%d bytes) = %v, want ErrMeasurementRegisterUnavailable over the size refusal", n, err)
		}
	}
}

// Measurements fills the typed value in the order of registerNames.
func TestMeasurementsSet(t *testing.T) {
	var m Measurements
	for i := range registerNames {
		m.set(i, [registerSize]byte{byte(i + 1)})
	}
	if m.MRTD[0] != 1 || m.MRConfigID[0] != 2 || m.MROwner[0] != 3 || m.MROwnerConfig[0] != 4 {
		t.Fatalf("static registers = %x %x %x %x", m.MRTD[0], m.MRConfigID[0], m.MROwner[0], m.MROwnerConfig[0])
	}
	for i := range rtmrCount {
		if m.RTMR[i][0] != byte(5+i) {
			t.Errorf("RTMR[%d][0] = %x, want %x", i, m.RTMR[i][0], 5+i)
		}
	}
}

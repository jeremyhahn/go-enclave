package inteltdx

import (
	"os"
	"path/filepath"
)

// report gets a TDREPORT for reportData through getReport and returns a copy
// of it.
func report(reportData [reportDataSize]byte) ([]byte, error) {
	req := tdxReportReq{ReportData: reportData}
	if err := getReport(&req); err != nil {
		return nil, err
	}
	out := make([]byte, tdReportSize)
	copy(out, req.TDReport[:])
	return out, nil
}

// readRegister reads the register file name under measurementsDir.
func readRegister(name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(measurementsDir, name)) //nolint:gosec // name is one of registerNames
	if err != nil {
		return nil, &MeasurementRegisterError{Register: name, Cause: err}
	}
	return b, nil
}

// writeRegister writes digest at offset 0 of the register file name under
// measurementsDir in one write, as the kernel requires of an RTMR extension.
func writeRegister(name string, digest [registerSize]byte) error {
	f, err := os.OpenFile(filepath.Join(measurementsDir, name), os.O_WRONLY, 0) //nolint:gosec // name is one of registerNames
	if err != nil {
		return &MeasurementRegisterError{Register: name, Cause: err}
	}
	if _, err := f.WriteAt(digest[:], 0); err != nil {
		_ = f.Close()
		return &MeasurementRegisterError{Register: name, Cause: err}
	}
	if err := f.Close(); err != nil {
		return &MeasurementRegisterError{Register: name, Cause: err}
	}
	return nil
}

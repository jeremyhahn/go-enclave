//go:build !(linux && amd64)

package inteltdx

import "runtime"

// platformRefusal is the refusal probe uses off linux/amd64: the guest device
// is unavailable for the platform, with no cause.
func platformRefusal() *GuestDeviceError {
	return &GuestDeviceError{Op: "platform " + runtime.GOOS + "/" + runtime.GOARCH}
}

// report refuses: off linux/amd64 there is no guest device.
func report([reportDataSize]byte) ([]byte, error) {
	return nil, platformRefusal()
}

// readRegister refuses, naming the register over the platform refusal.
func readRegister(name string) ([]byte, error) {
	return nil, &MeasurementRegisterError{Register: name, Cause: platformRefusal()}
}

// writeRegister refuses, naming the register over the platform refusal.
func writeRegister(name string, _ [registerSize]byte) error {
	return &MeasurementRegisterError{Register: name, Cause: platformRefusal()}
}

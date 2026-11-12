//go:build !linux

package imxele

// probeDevice is the stub off Linux, which has no TEE subsystem: the
// "platform" step refuses with no cause, so a main that registers the
// backend builds everywhere.
//
// The doc's "Off Linux arm64" stub is narrowed to off Linux: the TEE ioctl
// ABI is the same on every Linux architecture, so Linux hosts take the real
// path and refuse at "open" when the device is absent.
func probeDevice(path string) error {
	return &TEEDeviceError{Path: path, Op: opPlatform}
}

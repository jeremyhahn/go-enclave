//go:build linux && !cgo

package nvblackwell

import "errors"

// errNoCgo is why a cgo-less build cannot load NVML: go-nvml calls
// libnvidia-ml.so.1 through cgo.
var errNoCgo = errors.New("this build has no cgo, which go-nvml needs to load NVML")

// probeNVML refuses in a build without cgo: NVML cannot be loaded at all.
func probeNVML() error {
	return &NVMLError{Call: "load libnvidia-ml.so.1", Cause: errNoCgo}
}

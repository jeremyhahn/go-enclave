//go:build !linux

package nvblackwell

import "runtime"

// probeHost refuses: NVIDIA confidential computing runs in a linux CVM only
// (owner, 2026-10-15), so nothing is proposed for any other GOOS.
func probeHost() error {
	return &PlatformError{GOOS: runtime.GOOS}
}

//go:build !linux

package armtrustzone

import (
	"context"
	"runtime"
)

// client has no TEE to reach off linux: every call is a [PlatformError].
type client struct{}

// openClient refuses: the Linux TEE subsystem is linux's.
func openClient(string, teecUUID) (*client, error) {
	return nil, &PlatformError{GOOS: runtime.GOOS}
}

func (*client) getInfo(context.Context) (uint64, uint64, error) {
	return 0, 0, &PlatformError{GOOS: runtime.GOOS}
}

func (*client) fillRandom(context.Context, []byte, []chunk) error {
	return &PlatformError{GOOS: runtime.GOOS}
}

func (*client) seal(context.Context, []byte, []byte) ([]byte, error) {
	return nil, &PlatformError{GOOS: runtime.GOOS}
}

func (*client) unseal(context.Context, []byte, []byte, []byte) error {
	return &PlatformError{GOOS: runtime.GOOS}
}

func (*client) close() error { return &PlatformError{GOOS: runtime.GOOS} }

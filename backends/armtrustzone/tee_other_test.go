//go:build !linux

package armtrustzone

import (
	"errors"
	"runtime"
	"testing"
)

func TestConnectRefusesOffLinux(t *testing.T) {
	b, err := Connect("/dev/tee0")
	var pe *PlatformError
	if b != nil || !errors.Is(err, ErrUnsupportedPlatform) || !errors.As(err, &pe) || pe.GOOS != runtime.GOOS {
		t.Fatalf("Connect = %v, %v; want a PlatformError for %s", b, err, runtime.GOOS)
	}
}

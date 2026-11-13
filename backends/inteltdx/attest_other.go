//go:build !(linux && amd64)

package inteltdx

import (
	"context"
	"runtime"
)

// attest refuses off linux/amd64 as the probe does: the guest device is
// unavailable with no cause. An ended ctx still returns its own error first.
func attest(ctx context.Context, _ [reportDataSize]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, &GuestDeviceError{Op: "platform " + runtime.GOOS + "/" + runtime.GOARCH}
}

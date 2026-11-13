//go:build !(linux && amd64)

package inteltdx

import (
	"context"
	"runtime"
)

// probe refuses: a TD is an x86-64 virtual machine, and Linux is the only
// runtime target, so off linux/amd64 the guest device is unavailable with no
// cause. An ended ctx still returns its own error first.
func probe(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return &GuestDeviceError{Op: "platform " + runtime.GOOS + "/" + runtime.GOARCH}
}

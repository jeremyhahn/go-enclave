//go:build !(linux && amd64)

package intelsgx

import "context"

// probe refuses: SGX enclaves run linux/amd64 processes only.
func probe(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return &SGXEnclaveError{Op: "platform"}
}

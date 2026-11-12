//go:build !(linux && amd64)

package intelsgx

import "context"

// attestQuote refuses: SGX enclaves run linux/amd64 processes only.
func attestQuote(ctx context.Context, _ []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, &SGXEnclaveError{Op: "platform"}
}

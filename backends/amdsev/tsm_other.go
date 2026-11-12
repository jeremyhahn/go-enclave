//go:build !(linux && amd64)

package amdsev

import "context"

// requestReport refuses: SEV-SNP guests are Linux on amd64 only, so there is
// no report interface to reach here and the error carries no cause.
func requestReport(context.Context, string, []byte, func(string, error) error) ([]byte, error) {
	return nil, ErrSNPGuestUnavailable
}

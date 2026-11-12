//go:build !(linux && amd64)

package amdsev

import "context"

// deriveKey refuses: SEV-SNP guests are Linux on amd64 only, so there is no
// guest device to reach here and the error carries no cause.
func deriveKey(context.Context, string, keyRequest, []byte) error {
	return ErrSNPGuestUnavailable
}

package armtrustzone

import (
	"context"
	"errors"
	"fmt"

	enclave "github.com/jeremyhahn/go-enclave"
)

// The trusted application's sealing commands and the results they return
// besides TEEC_SUCCESS.
const (
	taCmdSeal   = 0x00000003 // TFW_TA_CMD_SEAL
	taCmdUnseal = 0x00000004 // TFW_TA_CMD_UNSEAL

	teecErrorBadFormat   = 0xffff0005 // TEE_ERROR_BAD_FORMAT
	teecErrorShortBuffer = 0xffff0010 // TEE_ERROR_SHORT_BUFFER
	teecErrorMACInvalid  = 0xffff3071 // TEE_ERROR_MAC_INVALID
)

// keyProtectorLabel is the associated data on every SEAL and UNSEAL.
const keyProtectorLabel = "go-enclave v1 TrustZone KeyProtector"

// sealOverhead sizes SEAL's first output buffer; sealMaxBlob bounds every sealed blob.
const (
	sealOverhead = 64
	sealMaxBlob  = 4096
)

var (
	_ enclave.KeyProtector   = (*KeyProtector)(nil)
	_ enclave.HealthReporter = (*KeyProtector)(nil)
)

// KeyProtector is an [enclave.KeyProtector] whose key lives in the trusted application (SEAL and UNSEAL).
type KeyProtector struct {
	b *Backend
}

// KeyProtector returns the backend's [KeyProtector].
func (b *Backend) KeyProtector() *KeyProtector { return &KeyProtector{b: b} }

// Protect seals key with the trusted application and returns a fresh blob; key is not kept or modified.
func (p *KeyProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p.b.c.seal(ctx, key, []byte(keyProtectorLabel))
}

// Unprotect opens blob into key, which must be the sealed key's length; on failure key is zeroed.
func (p *KeyProtector) Unprotect(ctx context.Context, blob, key []byte) (err error) {
	defer func() {
		if err != nil {
			clear(key)
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(blob) == 0 || len(blob) > sealMaxBlob || len(key) == 0 {
		return enclave.ErrSealedAuthentication
	}
	return p.b.c.unseal(ctx, blob, []byte(keyProtectorLabel), key)
}

// Health is nil: the key lives in the trusted application, and a failure to
// reach it is reported by the call that needs it.
func (*KeyProtector) Health() error { return nil }

// sealNext decides what follows a SEAL call: done, one larger retry, or an error.
func sealNext(err error, size int, got uint64, retried bool) (int, error) {
	if err == nil {
		if got == 0 || got > uint64(size) { //nolint:gosec // size is a buffer length, never negative
			return 0, fmt.Errorf("%w: SEAL returned %d bytes into a %d-byte buffer", ErrCommandFailed, got, size)
		}
		return 0, nil
	}
	var ce *CommandError
	if errors.As(err, &ce) && ce.Code == teecErrorShortBuffer && !retried &&
		got > uint64(size) && got <= sealMaxBlob { //nolint:gosec // size is a buffer length, never negative
		return int(got), nil
	}
	return 0, err
}

// unsealResult maps UNSEAL authentication failures to [enclave.ErrSealedAuthentication] and returns other errors as they are.
func unsealResult(err error, got uint64, want int) error {
	if err == nil {
		if got != uint64(want) { //nolint:gosec // want is a buffer length, never negative
			return enclave.ErrSealedAuthentication
		}
		return nil
	}
	var ce *CommandError
	if errors.As(err, &ce) && (ce.Code == teecErrorMACInvalid || ce.Code == teecErrorBadFormat || ce.Code == teecErrorShortBuffer) {
		return enclave.ErrSealedAuthentication
	}
	return err
}

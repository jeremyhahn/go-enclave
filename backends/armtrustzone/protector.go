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

// keyProtectorLabel is the associated data on every SEAL and UNSEAL, so a
// blob the trusted application sealed for another client never opens as a
// go-enclave key.
const keyProtectorLabel = "go-enclave v1 TrustZone KeyProtector"

// sealOverhead is how much larger than the key SEAL's first output buffer
// is; sealMaxBlob is the largest sealed blob SEAL may ask for, and the
// largest Unprotect hands to UNSEAL.
const (
	sealOverhead = 64
	sealMaxBlob  = 4096
)

var (
	_ enclave.KeyProtector   = (*KeyProtector)(nil)
	_ enclave.HealthReporter = (*KeyProtector)(nil)
)

// KeyProtector is an [enclave.KeyProtector] whose key lives in the trusted
// application: Protect seals a key with the TA's SEAL command and Unprotect
// opens it with UNSEAL, both under the fixed associated data
// "go-enclave v1 TrustZone KeyProtector". A blob is opaque to this package.
//
// Calls are safe for concurrent use; the backend's session lock serializes
// them at the TA. A KeyProtector is usable while its [Backend] is open, and
// its calls fail with [ErrBackendClosed] after the Backend's Close.
type KeyProtector struct {
	b *Backend
}

// KeyProtector returns the backend's [KeyProtector].
func (b *Backend) KeyProtector() *KeyProtector { return &KeyProtector{b: b} }

// Protect seals key with the trusted application and returns a fresh blob.
// The key is copied into driver shared memory for the call and that copy is
// wiped before Protect returns; key itself is neither kept nor modified.
//
// A context already ended is refused before the TA is called, with an error
// matching ctx.Err(). A TA or driver failure is a [CommandError],
// [DeviceError] or other error of this package.
func (p *KeyProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return p.b.c.seal(ctx, key, []byte(keyProtectorLabel))
}

// Unprotect opens blob with the trusted application and writes the key into
// key, which must be exactly as long as the key Protect sealed. A blob the
// TA does not authenticate, an empty or oversized blob, an empty key, or a
// key of another length fails with an error matching
// [enclave.ErrSealedAuthentication]. blob is copied, never kept or modified.
//
// A context already ended is refused before the TA is called, with an error
// matching ctx.Err(). On any failure key is zeroed.
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

// sealNext decides what follows a SEAL call that had an output buffer of
// size bytes and reported got: 0 with a nil error when the blob is done, a
// larger size to retry at once after TEE_ERROR_SHORT_BUFFER, or the error.
// A short buffer is retried once, and only up to sealMaxBlob.
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

// unsealResult maps an UNSEAL call that was to write want bytes and
// reported got: TEE_ERROR_MAC_INVALID (a tampered blob), TEE_ERROR_BAD_FORMAT
// (a truncated or forged one), TEE_ERROR_SHORT_BUFFER and a length other than
// want are [enclave.ErrSealedAuthentication]; any other error, such as
// TEE_ERROR_BAD_PARAMETERS for parameters this client got wrong, is returned
// as it is.
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

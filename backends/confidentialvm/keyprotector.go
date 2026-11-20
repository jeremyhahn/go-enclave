package confidentialvm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/jeremyhahn/go-enclave"
)

// sevGuestDevice is the SEV-SNP guest device. Tests point it elsewhere.
var sevGuestDevice = "/dev/sev-guest"

// MSG_KEY_REQ and MSG_KEY_RSP (SNP firmware ABI, publication 56860): the
// request is 32 bytes; the response is 64, whose STATUS is at offset 0 and
// whose DERIVED_KEY is the last 32 bytes.
const (
	keyRequestSize       = 32
	keyResponseSize      = 64
	keyResponseKeyOffset = 0x20
	derivedKeySize       = keyResponseSize - keyResponseKeyOffset
)

// ROOT_KEY_SELECT: the chip's VCEK, per chip and TCB.
const rootKeyVCEK uint32 = 0

// GUEST_FIELD_SELECT bits.
const (
	fieldPolicy      uint64 = 1 << 0
	fieldMeasurement uint64 = 1 << 3
	fieldTCBVersion  uint64 = 1 << 5
)

// sealFields is what the key is bound to (design Q6): the guest policy, the
// launch measurement and the TCB version.
const sealFields = fieldPolicy | fieldMeasurement | fieldTCBVersion

// The ATTESTATION_REPORT fields NewKeyProtector records.
const (
	snpReportSize   = 1184
	offGuestSVN     = 0x04
	offVMPL         = 0x30
	offCommittedTCB = 0x1e0
)

// The blob: a version byte, the 32-byte key request, the 96-bit GCM nonce,
// then the ciphertext and its 16-byte tag. Everything before the ciphertext
// is the GCM additional data.
const (
	blobVersion    = 1
	gcmNonceSize   = 12
	gcmTagSize     = 16
	blobHeaderSize = 1 + keyRequestSize + gcmNonceSize
)

// keyRequest is MSG_KEY_REQ: the root key, the guest fields mixed in, the
// VMPL to derive for, and the guest SVN and TCB version to derive for.
type keyRequest struct {
	rootKey    uint32
	fields     uint64
	vmpl       uint32
	guestSVN   uint32
	tcbVersion uint64
}

// encode lays r out as MSG_KEY_REQ, little-endian, bytes 4 to 7 reserved.
func (r keyRequest) encode() [keyRequestSize]byte {
	var b [keyRequestSize]byte
	binary.LittleEndian.PutUint32(b[0:], r.rootKey)
	binary.LittleEndian.PutUint64(b[8:], r.fields)
	binary.LittleEndian.PutUint32(b[16:], r.vmpl)
	binary.LittleEndian.PutUint32(b[20:], r.guestSVN)
	binary.LittleEndian.PutUint64(b[24:], r.tcbVersion)
	return b
}

// decodeKeyRequest reads MSG_KEY_REQ; reserved bytes that are not zero fail.
func decodeKeyRequest(b []byte) (keyRequest, bool) {
	if len(b) != keyRequestSize || binary.LittleEndian.Uint32(b[4:]) != 0 {
		return keyRequest{}, false
	}
	return keyRequest{
		rootKey:    binary.LittleEndian.Uint32(b[0:]),
		fields:     binary.LittleEndian.Uint64(b[8:]),
		vmpl:       binary.LittleEndian.Uint32(b[16:]),
		guestSVN:   binary.LittleEndian.Uint32(b[20:]),
		tcbVersion: binary.LittleEndian.Uint64(b[24:]),
	}, true
}

// tcbAtMost reports whether every component byte of the TCB version a is at
// most that of b: the firmware derives only for a TCB not above its own.
func tcbAtMost(a, b uint64) bool {
	for i := 0; i < 64; i += 8 {
		if byte(a>>i) > byte(b>>i) {
			return false
		}
	}
	return true
}

// decodeKeyResponse checks MSG_KEY_RSP's STATUS and copies DERIVED_KEY.
func decodeKeyResponse(resp *[keyResponseSize]byte, dst []byte) error {
	if s := binary.LittleEndian.Uint32(resp[0:]); s != 0 {
		return &FirmwareError{Status: s}
	}
	copy(dst, resp[keyResponseKeyOffset:])
	return nil
}

// KeyProtector is an [enclave.KeyProtector] for [enclave.ModePerOperation]
// keyed by the SEV-SNP derived key: a key the AMD Secure Processor derives
// from the chip's VCEK and this guest's policy, launch measurement and TCB
// version. A blob it makes opens only in a guest with the same measurement and
// policy on the same chip, at a TCB version not below the one recorded. Its
// methods are safe for concurrent use.
type KeyProtector struct {
	req keyRequest
}

var _ enclave.KeyProtector = (*KeyProtector)(nil)

// NewKeyProtector returns the KeyProtector of the SEV-SNP guest the program
// runs in. It requests one SNP report through configfs-tsm to record the
// guest's VMPL, guest SVN and committed TCB version, then derives one key to
// prove the request is served, and wipes it.
//
// It refuses with a *DerivedKeyError matching [ErrDerivedKeyUnavailable]: no
// /dev/sev-guest (in a TDX guest too, which has no derived sealing key), a
// refused device, no report, or a refused derivation. Off linux/amd64 it
// refuses with no Cause.
func NewKeyProtector() (*KeyProtector, error) {
	if !supported {
		return nil, &DerivedKeyError{}
	}
	if err := openDevice(sevGuestDevice); err != nil {
		return nil, err
	}
	var rd [reportDataSize]byte
	if _, err := rand.Read(rd[:]); err != nil {
		return nil, &DerivedKeyError{Op: "report", Cause: err}
	}
	report, err := request(tsmReportRoot, providerSEVGuest, &rd)
	if err != nil {
		return nil, &DerivedKeyError{Op: "report", Cause: err}
	}
	req, err := requestFromReport(report)
	if err != nil {
		return nil, err
	}
	kp := &KeyProtector{req: req}
	if err := kp.withKey(context.Background(), req, func([]byte) error { return nil }); err != nil {
		return nil, err
	}
	return kp, nil
}

// requestFromReport builds the key request from an SNP report's VMPL, guest
// SVN and committed TCB version.
func requestFromReport(report []byte) (keyRequest, error) {
	if len(report) < snpReportSize {
		return keyRequest{}, &DerivedKeyError{Op: "report",
			Cause: fmt.Errorf("report of %d bytes, want %d", len(report), snpReportSize)}
	}
	return keyRequest{
		rootKey:    rootKeyVCEK,
		fields:     sealFields,
		vmpl:       binary.LittleEndian.Uint32(report[offVMPL:]),
		guestSVN:   binary.LittleEndian.Uint32(report[offGuestSVN:]),
		tcbVersion: binary.LittleEndian.Uint64(report[offCommittedTCB:]),
	}, nil
}

// Protect seals key under a freshly derived SNP key with AES-256-GCM and a
// random nonce. The derived key lives in locked memory for the call and is
// wiped before it returns. A refused derivation is a *DerivedKeyError; an
// ended ctx is its error.
func (kp *KeyProtector) Protect(ctx context.Context, key []byte) ([]byte, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if kp == nil || kp.req.fields != sealFields {
		return nil, &DerivedKeyError{Op: "derived-key", Cause: errors.New("key protector not made by NewKeyProtector")}
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("%w: confidentialvm: empty key", enclave.ErrInvalidSize)
	}
	var blob []byte
	err := kp.withKey(ctx, kp.req, func(dk []byte) error {
		var err error
		blob, err = sealBlob(dk, kp.req, key)
		return err
	})
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// Unprotect opens blob into key, which must be the length that was sealed.
// It derives the key the blob's header names. A blob this guest's Protect did
// not make (truncated, altered, another binding, a TCB above this guest's,
// another length) matches [enclave.ErrSealedAuthentication] and leaves key
// unwritten; a refused derivation is a *DerivedKeyError; an ended ctx is its
// error.
func (kp *KeyProtector) Unprotect(ctx context.Context, blob []byte, key []byte) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	if kp == nil || kp.req.fields != sealFields {
		return &DerivedKeyError{Op: "derived-key", Cause: errors.New("key protector not made by NewKeyProtector")}
	}
	req, err := kp.blobRequest(blob, len(key))
	if err != nil {
		return err
	}
	return kp.withKey(ctx, req, func(dk []byte) error { return openBlob(dk, blob, key) })
}

// errBlob is the refusal of a blob this guest's Protect did not make.
func errBlob(why string) error {
	return fmt.Errorf("%w: confidentialvm: %s", enclave.ErrSealedAuthentication, why)
}

// blobRequest checks blob's layout and that its header binds as kp does, at a
// TCB version and guest SVN not above kp's, and returns the request it names.
func (kp *KeyProtector) blobRequest(blob []byte, keyLen int) (keyRequest, error) {
	if len(blob) != blobHeaderSize+keyLen+gcmTagSize || keyLen == 0 {
		return keyRequest{}, errBlob("blob length does not match the key")
	}
	if blob[0] != blobVersion {
		return keyRequest{}, errBlob("unknown blob version")
	}
	req, ok := decodeKeyRequest(blob[1 : 1+keyRequestSize])
	if !ok || req.rootKey != kp.req.rootKey || req.fields != kp.req.fields || req.vmpl != kp.req.vmpl {
		return keyRequest{}, errBlob("blob binds another key")
	}
	if req.guestSVN > kp.req.guestSVN || !tcbAtMost(req.tcbVersion, kp.req.tcbVersion) {
		return keyRequest{}, errBlob("blob derives for a TCB above this guest's")
	}
	return req, nil
}

// newGCM is AES-256-GCM under dk.
func newGCM(dk []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealBlob seals key under dk into a blob whose header is req.
func sealBlob(dk []byte, req keyRequest, key []byte) ([]byte, error) {
	aead, err := newGCM(dk)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, blobHeaderSize, blobHeaderSize+len(key)+gcmTagSize)
	blob[0] = blobVersion
	enc := req.encode()
	copy(blob[1:], enc[:])
	nonce := blob[1+keyRequestSize : blobHeaderSize]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(blob, nonce, key, blob[:blobHeaderSize]), nil
}

// openBlob opens blob under dk into key, writing key only once the tag holds.
func openBlob(dk, blob, key []byte) error {
	aead, err := newGCM(dk)
	if err != nil {
		return err
	}
	nonce := blob[1+keyRequestSize : blobHeaderSize]
	out, err := aead.Open(nil, nonce, blob[blobHeaderSize:], blob[:blobHeaderSize])
	if err != nil {
		return errBlob("blob does not authenticate")
	}
	copy(key, out)
	clear(out)
	return nil
}

// withKey derives the key req selects into locked memory, runs fn on it and
// wipes and frees it on every path.
func (kp *KeyProtector) withKey(ctx context.Context, req keyRequest, fn func(dk []byte) error) (err error) {
	mem, err := enclave.NewMemorySized(derivedKeySize)
	if err != nil {
		return &DerivedKeyError{Op: "memory", Cause: err}
	}
	defer func() {
		if derr := mem.Destroy(); derr != nil && err == nil {
			err = &DerivedKeyError{Op: "memory", Cause: derr}
		}
	}()
	return mem.WithBytes(func(dk []byte) error {
		defer clear(dk)
		if err := deriveKey(ctx, sevGuestDevice, req, dk); err != nil {
			return err
		}
		return fn(dk)
	})
}

// receiveKey runs fill on a response buffer in locked memory, then copies
// the derived key into dst; the buffer is wiped and freed on every path.
func receiveKey(dst []byte, fill func(resp *[keyResponseSize]byte) error) (err error) {
	mem, err := enclave.NewMemorySized(keyResponseSize)
	if err != nil {
		return &DerivedKeyError{Op: "memory", Cause: err}
	}
	defer func() {
		if derr := mem.Destroy(); derr != nil && err == nil {
			clear(dst)
			err = &DerivedKeyError{Op: "memory", Cause: derr}
		}
	}()
	return mem.WithBytes(func(b []byte) error {
		defer clear(b)
		if len(b) != keyResponseSize || len(dst) != derivedKeySize {
			return &DerivedKeyError{Op: "memory", Cause: enclave.ErrInvalidSize}
		}
		resp := (*[keyResponseSize]byte)(b)
		if err := fill(resp); err != nil {
			return err
		}
		if err := decodeKeyResponse(resp, dst); err != nil {
			return &DerivedKeyError{Op: "derived-key", Cause: err}
		}
		return nil
	})
}

// firmwareError splits exitinfo2 into the firmware's and the hypervisor's
// error words.
func firmwareError(exitInfo2 uint64, errno error) *FirmwareError {
	return &FirmwareError{
		FWError:  uint32(exitInfo2), //nolint:gosec // G115: the low half, by definition
		VMMError: uint32(exitInfo2 >> 32),
		Errno:    errno,
	}
}

// ctxErr is ctx.Err(), nil for a nil ctx (the background context).
func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

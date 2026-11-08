package tpm

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"

	"github.com/jeremyhahn/go-enclave"
)

// The provider marshals the two commands that carry the key, TPM2_Create and
// TPM2_Unseal, itself. go-tpm marshals TPM2_Create's inSensitive in clear
// into heap buffers before it encrypts it, and decrypts TPM2_Unseal's outData
// in place in a heap buffer it never wipes, so a key passed through it would
// outlive the call. Here the key is in clear only in the caller's buffer, a
// locked parameter buffer, and the transport's locked response buffer, and
// the session's exported Encrypt, Decrypt, Authorize and Validate work on
// those buffers in place.

const (
	tagSessions   = 0x8002 // TPM_ST_SESSIONS
	cmdHeaderSize = 10     // tag, commandSize, commandCode
	rspHeaderSize = 10     // tag, responseSize, responseCode
)

// errMalformedResponse is a response whose sizes do not add up.
var errMalformedResponse = errors.New("the TPM response is malformed")

func (d *tpmDevice) create(ctx context.Context, parent object, s session, data []byte) (public, private []byte, err error) {
	defer d.t.wipe()
	if len(data) > maxKeyBytes {
		return nil, nil, fmt.Errorf("a %d-byte key exceeds the %d-byte limit", len(data), maxKeyBytes)
	}
	inPublic := tpm2.Marshal(tpm2.New2B(sealedTemplate(nil)))
	// inSensitive is a TPM2B_SENSITIVE_CREATE: its size, an empty userAuth
	// and data. Then inPublic, an empty outsideInfo, and no creation PCRs.
	sensitive := 2 + 2 + len(data)
	params, err := d.t.alloc.alloc(2 + sensitive + len(inPublic) + 2 + 4)
	if err != nil {
		return nil, nil, err
	}
	defer d.t.alloc.free(params)
	defer enclave.Wipe(params)
	binary.BigEndian.PutUint16(params, uint16(sensitive))
	binary.BigEndian.PutUint16(params[4:], uint16(len(data)))
	copy(params[6:], data)
	copy(params[2+sensitive:], inPublic)
	if err := s.auth.NewNonceCaller(); err != nil {
		return nil, nil, err
	}
	if err := s.auth.Encrypt(params[2 : 2+sensitive]); err != nil {
		return nil, nil, err
	}
	rsp, err := d.execute(ctx, tpm2.TPMCCCreate, parent, s, params)
	if err != nil {
		return nil, nil, err
	}
	// outPrivate then outPublic; creationData, creationHash and
	// creationTicket follow and are not kept.
	private, rest, ok := cut2B(rsp)
	if !ok {
		return nil, nil, errMalformedResponse
	}
	public, _, ok = cut2B(rest)
	if !ok {
		return nil, nil, errMalformedResponse
	}
	return append([]byte(nil), public...), append([]byte(nil), private...), nil
}

func (d *tpmDevice) unseal(ctx context.Context, obj object, s session, dst []byte) (int, error) {
	defer d.t.wipe()
	if err := s.auth.NewNonceCaller(); err != nil {
		return 0, err
	}
	rsp, err := d.execute(ctx, tpm2.TPMCCUnseal, obj, s, nil)
	if err != nil {
		return 0, err
	}
	out, _, ok := cut2B(rsp)
	if !ok {
		return 0, errMalformedResponse
	}
	// outData is decrypted in the transport's locked buffer, which the
	// deferred wipe clears.
	if err := s.auth.Decrypt(out); err != nil {
		return 0, err
	}
	if len(out) <= len(dst) {
		copy(dst, out)
	}
	return len(out), nil
}

// execute sends a command with one handle, authorized by s, whose parameter
// area is params as it goes on the wire, encrypted under s's nonceCaller,
// which the caller has refreshed, and returns the response's
// parameter area once s has validated it. The response aliases the
// transport's buffer.
func (d *tpmDevice) execute(ctx context.Context, cc tpm2.TPMCC, h object, s session, params []byte) ([]byte, error) {
	names := []tpm2.TPM2BName{h.name}
	auth, err := s.auth.Authorize(cc, params, nil, names, 0)
	if err != nil {
		return nil, err
	}
	area := tpm2.Marshal(auth)
	size := cmdHeaderSize + 4 + 4 + len(area) + len(params)
	if size > maxResponseBytes {
		return nil, fmt.Errorf("a %d-byte command exceeds the %d-byte limit", size, maxResponseBytes)
	}
	cmd, err := d.t.alloc.alloc(size)
	if err != nil {
		return nil, err
	}
	defer d.t.alloc.free(cmd)
	binary.BigEndian.PutUint16(cmd, tagSessions)
	binary.BigEndian.PutUint32(cmd[2:], uint32(size))
	binary.BigEndian.PutUint32(cmd[6:], uint32(cc))
	binary.BigEndian.PutUint32(cmd[10:], uint32(h.handle))
	binary.BigEndian.PutUint32(cmd[14:], uint32(len(area)))
	copy(cmd[18:], area)
	copy(cmd[18+len(area):], params)
	rsp, err := d.t.send(ctx, cmd) // send wipes cmd.
	if err != nil {
		return nil, err
	}
	if rc := tpm2.TPMRC(binary.BigEndian.Uint32(rsp[6:])); rc != tpm2.TPMRCSuccess {
		return nil, rc
	}
	if binary.BigEndian.Uint16(rsp) != tagSessions || len(rsp) < rspHeaderSize+4 {
		return nil, errMalformedResponse
	}
	n := binary.BigEndian.Uint32(rsp[rspHeaderSize:])
	rest := rsp[rspHeaderSize+4:]
	if uint64(n) > uint64(len(rest)) {
		return nil, errMalformedResponse
	}
	parms := rest[:n]
	rspAuth, err := tpm2.Unmarshal[tpm2.TPMSAuthResponse](rest[n:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errMalformedResponse, err)
	}
	if err := s.auth.Validate(tpm2.TPMRCSuccess, cc, parms, names, 0, rspAuth); err != nil {
		return nil, err
	}
	return parms, nil
}

// cut2B splits a TPM2B's contents off the front of b.
func cut2B(b []byte) (contents, rest []byte, ok bool) {
	if len(b) < 2 {
		return nil, nil, false
	}
	n := int(binary.BigEndian.Uint16(b))
	if 2+n > len(b) {
		return nil, nil, false
	}
	return b[2 : 2+n], b[2+n:], true
}

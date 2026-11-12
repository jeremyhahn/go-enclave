package inteltdx

import (
	"context"
	"fmt"

	enclave "github.com/jeremyhahn/go-enclave"
)

// EvidenceFormat is the Format of the Evidence Attest returns: a TD quote,
// exactly as configfs-tsm's outblob returned it, in the format of Intel's TDX
// DCAP Quoting Library API. Q5, recommended answer: the kernel's provider
// value, which the kernel defines as the name of outblob's format, so the
// backend invents no second name.
const EvidenceFormat = tsmProvider

// Attest returns a TD quote whose REPORTDATA carries nonce, through a
// configfs-tsm report directory of its own (the design's "Attestation").
// nonce is 1 to 64 bytes; any other length is [enclave.ErrInvalidNonce]
// before any request. The provider must read tdx_guest and the generation
// must count exactly this call's write, or the call fails with a
// [*TSMReportError] (its Cause [ErrTSMReportConflict] for a moved
// generation). Calls on one Backend are serialized; a call waiting for
// another returns its ctx's error as soon as ctx ends. Off a TD it refuses
// with a [*TSMReportError] naming the step; off linux/amd64, or on a Backend
// [New] did not make, with a [*GuestDeviceError]. An ended ctx returns its
// own error.
func (b *Backend) Attest(ctx context.Context, nonce []byte) (enclave.Evidence, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	rd, err := reportData(nonce)
	if err != nil {
		return enclave.Evidence{}, err
	}
	if err := ctx.Err(); err != nil {
		return enclave.Evidence{}, err
	}
	if err := b.unconstructed(); err != nil {
		return enclave.Evidence{}, err
	}
	select {
	case b.slot <- struct{}{}:
	case <-ctx.Done():
		return enclave.Evidence{}, ctx.Err()
	}
	defer func() { <-b.slot }()
	q, err := attest(ctx, rd)
	if err != nil {
		return enclave.Evidence{}, err
	}
	return enclave.Evidence{Format: EvidenceFormat, Data: q}, nil
}

// reportData lays nonce out as REPORTDATA. Q4, recommended answer: the nonce
// zero-padded to 64 bytes, what the kernel's inblob takes and what Intel's
// verifiers compare, so a relying party checks REPORTDATA with no
// construction of ours. The backend writes all 64 bytes itself, never relying
// on the kernel's buffer. A nonce and the same nonce with trailing zeros give
// one REPORTDATA: a relying party that cares sends 64 bytes.
func reportData(nonce []byte) ([reportDataSize]byte, error) {
	var rd [reportDataSize]byte
	if len(nonce) == 0 || len(nonce) > reportDataSize {
		return rd, fmt.Errorf("%w: intel-tdx: nonce of %d bytes, want 1 to %d",
			enclave.ErrInvalidNonce, len(nonce), reportDataSize)
	}
	copy(rd[:], nonce)
	return rd, nil
}

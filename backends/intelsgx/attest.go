package intelsgx

import (
	"context"

	enclave "github.com/jeremyhahn/go-enclave"
)

// EvidenceFormat is the [enclave.Evidence] format Attest returns: the
// version 3 ECDSA quote of the DCAP Quote Library API, byte for byte, its
// certification data as the quoting service returns it. Open question Q6,
// recommended option: the quote alone, no wrapper; the verifier fetches the
// collateral.
const EvidenceFormat = "sgx-quote"

var _ enclave.Attester = (*Backend)(nil)

// Attest returns a quote whose REPORT_DATA is nonce zero-padded to 64 bytes
// (Q6, recommended option); the verifier compares it against the nonce it
// issued and its length. A nonce empty or over 64 bytes is
// [enclave.ErrInvalidNonce] before any request. Calls on one backend are
// serialised by its lock, and the quote must carry the padded nonce: a quote
// another writer in the process raced is [ErrReportDataMismatch], never
// returned.
//
// Outside a usable enclave it returns an error matching [ErrSGXUnavailable]
// naming the step; a failed quote request matches [ErrSGXQuote]. It returns
// ctx.Err() when ctx has ended before the request; a file read the library
// OS is blocking in is not interrupted. A nil ctx is context.Background.
func (b *Backend) Attest(ctx context.Context, nonce []byte) (enclave.Evidence, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	reportData, err := padNonce(nonce)
	if err != nil {
		return enclave.Evidence{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return enclave.Evidence{}, err
	}
	quote, err := attestQuote(ctx, reportData)
	if err != nil {
		return enclave.Evidence{}, err
	}
	return enclave.Evidence{Format: EvidenceFormat, Data: quote}, nil
}

// padNonce returns nonce zero-padded to REPORT_DATA's 64 bytes, in a new
// slice, or [enclave.ErrInvalidNonce] when nonce is empty or longer.
func padNonce(nonce []byte) ([]byte, error) {
	if len(nonce) == 0 || len(nonce) > reportDataSize {
		return nil, enclave.ErrInvalidNonce
	}
	reportData := make([]byte, reportDataSize)
	copy(reportData, nonce)
	return reportData, nil
}

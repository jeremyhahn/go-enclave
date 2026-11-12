package nvblackwell

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"

	enclave "github.com/jeremyhahn/go-enclave"
)

// EvidenceFormat is the Format of the Evidence [Backend.Attest] returns: a
// CMW collection in the CMW JSON form.
const EvidenceFormat = "application/cmw+json"

// maxNonce is the longest nonce Attest takes, the seam's bound.
const maxNonce = 64

// The member media types. Only the PEM chain type is registered; the others
// are this module's own, named under its vendor tree.
const (
	mediaTypeVendorPrefix = "application/vnd.go-enclave."
	mediaTypeGPUReport    = mediaTypeVendorPrefix + "nvidia-gpu-report"
	mediaTypeCECReport    = mediaTypeVendorPrefix + "nvidia-cec-report"
)

// gpuEvidence is what one GPU returned: its SPDM measurement report over the
// GPU nonce, the CEC report when the part has one, and both chains.
type gpuEvidence struct {
	Report               []byte
	CECReport            []byte
	CertChain            []byte
	AttestationCertChain []byte
}

var _ enclave.Attester = (*Backend)(nil)

// Attest returns one Evidence covering the CVM and every GPU it sees, under
// one nonce: inner's evidence over nonce as given and each GPU's report over
// SHA-256(nonce), the 32 bytes a GPU binds. Data is a CMW collection: "cpu",
// then "gpu0", "gpu1", ..., each a collection of "report", "cec-report" (when
// present), "cert-chain" and "attestation-cert-chain". A nonce outside 1 to
// 64 bytes is enclave.ErrInvalidNonce. On a host Probe refuses, Attest
// returns Probe's typed error and never asks inner. Verifying the evidence
// is the relying party's.
func (b *Backend) Attest(ctx context.Context, nonce []byte) (enclave.Evidence, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return enclave.Evidence{}, err
		}
	}
	if len(nonce) == 0 || len(nonce) > maxNonce {
		return enclave.Evidence{}, enclave.ErrInvalidNonce
	}
	if err := b.Probe(ctx); err != nil {
		return enclave.Evidence{}, err
	}
	cpu, err := b.inner.Attest(ctx, nonce)
	if err != nil {
		return enclave.Evidence{}, err
	}
	gpus, err := gatherGPUEvidence(gpuNonce(nonce))
	if err != nil {
		return enclave.Evidence{}, err
	}
	data, err := encodeEvidence(cpu, gpus)
	if err != nil {
		return enclave.Evidence{}, err
	}
	return enclave.Evidence{Format: EvidenceFormat, Data: data}, nil
}

// gpuNonce is the 32 bytes each GPU binds: SHA-256 of the caller's nonce,
// so every byte of a 1- to 64-byte nonce reaches the report.
func gpuNonce(nonce []byte) [32]byte { return sha256.Sum256(nonce) }

// encodeEvidence writes the CMW collection Attest returns.
func encodeEvidence(cpu enclave.Evidence, gpus []gpuEvidence) ([]byte, error) {
	if len(gpus) == 0 {
		return nil, fmt.Errorf("%w: no GPU evidence", errMalformedCMW)
	}
	if !isMediaSubtypeToken(cpu.Format) {
		return nil, fmt.Errorf("%w: CPU evidence format %s", errMalformedCMW, strconv.Quote(cpu.Format))
	}
	c := cmwCollection{
		"cpu": cmwRecord{Type: mediaTypeVendorPrefix + cpu.Format, Value: cpu.Data, Ind: cmwIndEvidence},
	}
	for i, g := range gpus {
		m := cmwCollection{
			"report":                 cmwRecord{Type: mediaTypeGPUReport, Value: g.Report, Ind: cmwIndEvidence},
			"cert-chain":             cmwRecord{Type: mediaTypePEMChain, Value: g.CertChain},
			"attestation-cert-chain": cmwRecord{Type: mediaTypePEMChain, Value: g.AttestationCertChain},
		}
		if len(g.CECReport) > 0 {
			m["cec-report"] = cmwRecord{Type: mediaTypeCECReport, Value: g.CECReport, Ind: cmwIndEvidence}
		}
		c["gpu"+strconv.Itoa(i)] = m
	}
	return encodeCMW(c)
}

// isMediaSubtypeToken reports whether s is a non-empty run of lower-case
// letters, digits, '-' and '.', safe to end a media subtype.
func isMediaSubtypeToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

package intelsgx

import (
	"context"
	"os"
	"strings"
)

// attestQuote checks that attestation_type still reads "dcap", then requests
// a quote over reportData through quoteOver and checks that it is a version 3
// ECDSA quote carrying reportData at REPORT_DATA.
func attestQuote(ctx context.Context, reportData []byte) ([]byte, error) {
	typ, err := os.ReadFile(attestationDir + "/attestation_type")
	if err != nil {
		return nil, &SGXEnclaveError{Op: "attestation_type", Cause: err}
	}
	if v := strings.TrimRight(string(typ), "\x00\n"); v != "dcap" {
		return nil, &SGXEnclaveError{Op: "attestation_type", Cause: &AttestationTypeError{Value: v}}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	quote, qerr := quoteOver(reportData)
	if qerr != nil {
		return nil, qerr
	}
	if err := checkQuote(quote, reportData); err != nil {
		return nil, err
	}
	return quote, nil
}

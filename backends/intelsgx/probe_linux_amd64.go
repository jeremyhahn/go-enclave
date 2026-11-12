package intelsgx

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"sync"
)

// attestationDir is Gramine's attestation pseudo-filesystem, present inside
// the enclave only. The backend reaches SGX through it alone (open question
// Q3, recommended option).
const attestationDir = "/dev/attestation"

// attestationMu serializes the backend's writes to user_report_data and reads
// of quote: the files are per process, so two writers in one process race.
var attestationMu sync.Mutex

// probe is the detection probe (open question Q5, recommended option): it
// checks ctx, reads attestation_type (it must be "dcap"), reads the enclave's
// own report and refuses a set DEBUG attribute, then requests one quote over
// a fresh random nonce and checks that it is a version 3 ECDSA quote with
// that nonce at REPORT_DATA. It verifies nothing else.
//
// Each step is checked against ctx before it runs; a file read the library OS
// is blocking in is not interrupted.
func probe(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	typ, err := os.ReadFile(attestationDir + "/attestation_type")
	if err != nil {
		return &SGXEnclaveError{Op: "attestation_type", Cause: err}
	}
	if v := strings.TrimRight(string(typ), "\x00\n"); v != "dcap" {
		return &SGXEnclaveError{Op: "attestation_type", Cause: &AttestationTypeError{Value: v}}
	}

	if err := ctx.Err(); err != nil {
		return err
	}
	report, err := os.ReadFile(attestationDir + "/report")
	if err != nil {
		return &SGXEnclaveError{Op: opReport, Cause: err}
	}
	if err := checkReport(report); err != nil {
		op := "report"
		if errors.Is(err, ErrDebugEnclave) {
			op = "debug"
		}
		return &SGXEnclaveError{Op: op, Cause: err}
	}

	nonce := make([]byte, reportDataSize)
	if _, err := rand.Read(nonce); err != nil {
		return &SGXEnclaveError{Op: "random", Cause: err}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	quote, qerr := quoteOver(nonce)
	if qerr != nil {
		return &SGXEnclaveError{Op: qerr.Op, Cause: qerr}
	}
	if err := checkQuote(quote, nonce); err != nil {
		return &SGXEnclaveError{Op: opQuote, Cause: err}
	}
	return nil
}

// quoteOver writes reportData (64 bytes) to user_report_data and reads the
// quote, under attestationMu.
func quoteOver(reportData []byte) ([]byte, *SGXQuoteError) {
	attestationMu.Lock()
	defer attestationMu.Unlock()
	// O_WRONLY without O_CREATE: the pseudo-file exists in an enclave, and
	// nothing is ever created outside one.
	f, err := os.OpenFile(attestationDir+"/user_report_data", os.O_WRONLY, 0)
	if err != nil {
		return nil, &SGXQuoteError{Op: "user_report_data", Cause: err}
	}
	_, err = f.Write(reportData)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, &SGXQuoteError{Op: "user_report_data", Cause: err}
	}
	quote, err := os.ReadFile(attestationDir + "/quote")
	if err != nil {
		return nil, &SGXQuoteError{Op: opQuote, Cause: err}
	}
	return quote, nil
}

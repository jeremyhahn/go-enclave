//go:build unix

package intelsgx

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	enclave "github.com/jeremyhahn/go-enclave"
)

// The hardware runner hands the SGX conformance harness its relying party
// through the enclave's fixed environment (the signed Gramine manifest):
//
//   - envSGXQuoteVerifier: the absolute path of a DCAP quote verifier, a
//     trusted file of the manifest. It is run as
//     `<verifier> <MRENCLAVE hex> <REPORT_DATA hex>` with the quote on
//     stdin, and exits 0 only when it has checked the PCK chain to the Intel
//     SGX Root CA, the QE report and identity, the quote signature, the TCB
//     status, REPORT_DATA, the expected MRENCLAVE and DEBUG clear.
//   - envSGXMRENCLAVE: the expected MRENCLAVE, 64 hex digits, from the
//     runner's signing step.
//
// With either missing the harness refuses, and the conformance test fails.
const (
	envSGXQuoteVerifier = "GO_ENCLAVE_SGX_QUOTE_VERIFIER"
	envSGXMRENCLAVE     = "GO_ENCLAVE_SGX_MRENCLAVE"
)

// mrEnclaveOffset is MRENCLAVE's offset in the ISV enclave report body.
const mrEnclaveOffset = 64

var (
	errQuoteNotVerified    = errors.New("intelsgx test: quote not verified")
	errMeasurementMismatch = errors.New("intelsgx test: MRENCLAVE is not the expected measurement")
)

// quoteVerifier is the harness's relying party: local checks of the quote's
// shape, nonce, DEBUG bit and measurement, then the runner's DCAP verifier,
// whose verdict is the result.
type quoteVerifier struct {
	command   string
	mrenclave []byte
}

// quoteVerifierFromEnv reads the verifier and expected measurement the
// runner supplies; it refuses, naming the variable, when either is missing
// or malformed.
func quoteVerifierFromEnv(getenv func(string) string) (*quoteVerifier, error) {
	cmd := getenv(envSGXQuoteVerifier)
	if cmd == "" || !filepath.IsAbs(cmd) {
		return nil, fmt.Errorf("%s must name the hardware runner's DCAP quote verifier by absolute path (got %q); "+
			"without it no quote is verified", envSGXQuoteVerifier, cmd)
	}
	mr, err := hex.DecodeString(getenv(envSGXMRENCLAVE))
	if err != nil || len(mr) != 32 {
		return nil, fmt.Errorf("%s must hold the expected MRENCLAVE as 64 hex digits from the runner's signing step "+
			"(got %q)", envSGXMRENCLAVE, getenv(envSGXMRENCLAVE))
	}
	return &quoteVerifier{command: cmd, mrenclave: mr}, nil
}

// verify returns nil only when the local checks pass and the runner's
// verifier accepts the quote for this nonce and measurement.
func (v *quoteVerifier) verify(nonce []byte, ev enclave.Evidence) error {
	if ev.Format != EvidenceFormat {
		return fmt.Errorf("%w: evidence format %q, want %q", errQuoteNotVerified, ev.Format, EvidenceFormat)
	}
	rd, err := padNonce(nonce)
	if err != nil {
		return fmt.Errorf("%w: %w", errQuoteNotVerified, err)
	}
	if err := checkQuote(ev.Data, rd); err != nil {
		return fmt.Errorf("%w: %w", errQuoteNotVerified, err)
	}
	if binary.LittleEndian.Uint64(ev.Data[quoteHeaderSize+attributesOffset:])&flagDebug != 0 {
		return fmt.Errorf("%w: %w", errQuoteNotVerified, ErrDebugEnclave)
	}
	at := quoteHeaderSize + mrEnclaveOffset
	if subtle.ConstantTimeCompare(ev.Data[at:at+32], v.mrenclave) != 1 {
		return fmt.Errorf("%w: %w", errQuoteNotVerified, errMeasurementMismatch)
	}
	cmd := exec.Command(v.command, hex.EncodeToString(v.mrenclave), hex.EncodeToString(rd))
	cmd.Stdin = bytes.NewReader(ev.Data)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s refused the quote: %w: %s", errQuoteNotVerified, v.command, err, strings.TrimSpace(string(out)))
	}
	return nil
}

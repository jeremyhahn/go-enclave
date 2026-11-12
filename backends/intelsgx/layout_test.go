package intelsgx

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// The buffers below are laid out by hand from the documented structures:
// sgx_report_t (a 384-byte sgx_report_body_t, a 32-byte key id, a 16-byte
// MAC; ATTRIBUTES.FLAGS at body offset 48, DEBUG bit 0x2) and the DCAP quote
// version 3 (a 48-byte header whose version and attestation key type are its
// first two little-endian uint16s, then the ISV enclave report body, whose
// REPORT_DATA is at body offset 320). They test the parsers, not a device.

func report(flags uint64) []byte {
	b := make([]byte, 432)
	binary.LittleEndian.PutUint64(b[48:], flags)
	return b
}

func quote(version, keyType uint16, reportData []byte) []byte {
	b := make([]byte, 48+384+4) // header, body, signature data length
	binary.LittleEndian.PutUint16(b[0:], version)
	binary.LittleEndian.PutUint16(b[2:], keyType)
	copy(b[48+320:], reportData)
	return b
}

func nonce() []byte {
	n := make([]byte, 64)
	for i := range n {
		n[i] = byte(i + 1)
	}
	return n
}

func TestCheckReport(t *testing.T) {
	if err := checkReport(report(0x4)); err != nil { // MODE64BIT only
		t.Fatalf("checkReport(production) = %v, want nil", err)
	}
	if err := checkReport(report(0x2 | 0x4)); !errors.Is(err, ErrDebugEnclave) {
		t.Fatalf("checkReport(DEBUG) = %v, want ErrDebugEnclave", err)
	}
	var le *LayoutError
	if err := checkReport(make([]byte, 431)); !errors.As(err, &le) || le.Structure != "report" || le.Want != 432 || le.Got != 431 {
		t.Fatalf("checkReport(short) = %v, want a report LayoutError 432/431", err)
	}
}

func TestCheckQuote(t *testing.T) {
	n := nonce()
	if err := checkQuote(quote(3, 2, n), n); err != nil {
		t.Fatalf("checkQuote(v3 ECDSA, nonce) = %v, want nil", err)
	}

	cases := []struct {
		name  string
		quote []byte
		op    string
		cause any
	}{
		{"version 4", quote(4, 2, n), "quote", new(*QuoteFormatError)},
		{"key type 3", quote(3, 3, n), "quote", new(*QuoteFormatError)},
		{"short", quote(3, 2, n)[:431], "quote", new(*LayoutError)},
		{"other report data", quote(3, 2, bytes.Repeat([]byte{0xee}, 64)), "report_data", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkQuote(tc.quote, n)
			var qe *SGXQuoteError
			if !errors.As(err, &qe) || !errors.Is(err, ErrSGXQuote) {
				t.Fatalf("checkQuote = %v, want an SGXQuoteError", err)
			}
			if qe.Op != tc.op {
				t.Fatalf("Op = %q, want %q", qe.Op, tc.op)
			}
			if tc.cause == nil {
				if !errors.Is(err, ErrReportDataMismatch) {
					t.Fatalf("checkQuote = %v, want ErrReportDataMismatch", err)
				}
				return
			}
			if !errors.As(err, tc.cause) {
				t.Fatalf("checkQuote = %v, want cause %T", err, tc.cause)
			}
		})
	}
}

func TestErrorText(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{&SGXEnclaveError{Op: "platform"}, "intelsgx: not in a usable SGX enclave: platform"},
		{&SGXEnclaveError{Op: "debug", Cause: ErrDebugEnclave}, "intelsgx: not in a usable SGX enclave: debug: intelsgx: the enclave is a debug enclave"},
		{&SGXEnclaveError{Op: "attestation_type", Cause: &AttestationTypeError{Value: "none"}}, `intelsgx: not in a usable SGX enclave: attestation_type: intelsgx: attestation type is not dcap: "none"`},
		{&SGXQuoteError{Op: "quote", Cause: &QuoteFormatError{Version: 4, KeyType: 2}}, "intelsgx: the SGX quote request failed: quote: intelsgx: quote is version 4 with attestation key type 2, want version 3 with type 2 (ECDSA P-256)"},
		{&LayoutError{Structure: "quote", Want: 432, Got: 10}, "intelsgx: quote is 10 bytes, want at least 432"},
	}
	for _, tc := range cases {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("Error() = %q, want %q", got, tc.want)
		}
	}
	if errors.Is(&SGXEnclaveError{Op: "x"}, ErrSGXQuote) || errors.Is(&SGXQuoteError{Op: "x"}, ErrSGXUnavailable) {
		t.Error("ErrSGXUnavailable and ErrSGXQuote must not match each other's errors")
	}
}

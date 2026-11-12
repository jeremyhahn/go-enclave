package intelsgx

import (
	"crypto/subtle"
	"encoding/binary"
)

// The documented layouts the backend reads. Nothing else in a report or a
// quote is parsed: go-enclave never appraises evidence; the relying party's
// verifier does.
const (
	// reportBodySize is sizeof(sgx_report_body_t).
	reportBodySize = 384
	// reportSize is sizeof(sgx_report_t): the body, a 32-byte key id and a
	// 16-byte MAC.
	reportSize = reportBodySize + 32 + 16
	// attributesOffset is ATTRIBUTES.FLAGS's offset in the report body.
	attributesOffset = 48
	// flagDebug is SGX_FLAGS_DEBUG in ATTRIBUTES.FLAGS.
	flagDebug = 0x2
	// reportDataOffset is REPORT_DATA's offset in the report body.
	reportDataOffset = 320
	// reportDataSize is REPORT_DATA's size.
	reportDataSize = 64

	// quoteHeaderSize is sizeof(sgx_quote_header_t) in a DCAP quote v3.
	quoteHeaderSize = 48
	// quoteMinSize is the header and the ISV enclave report body.
	quoteMinSize = quoteHeaderSize + reportBodySize
	// quoteVersion is the DCAP Quote Library API's quote version.
	quoteVersion = 3
	// keyTypeECDSAP256 is the quote header's attestation key type for
	// ECDSA-256-with-P-256.
	keyTypeECDSAP256 = 2
)

// checkReport refuses an sgx_report_t shorter than its layout with a
// [*LayoutError] and one whose ATTRIBUTES set DEBUG with [ErrDebugEnclave].
func checkReport(report []byte) error {
	if len(report) < reportSize {
		return &LayoutError{Structure: "report", Want: reportSize, Got: len(report)}
	}
	if binary.LittleEndian.Uint64(report[attributesOffset:])&flagDebug != 0 {
		return ErrDebugEnclave
	}
	return nil
}

// checkQuote checks that quote is a DCAP version 3 ECDSA quote whose
// REPORT_DATA is reportData, the 64 bytes the backend wrote. It verifies
// nothing else (open question Q5, recommended option).
func checkQuote(quote, reportData []byte) error {
	if len(quote) < quoteMinSize {
		return &SGXQuoteError{Op: "quote", Cause: &LayoutError{Structure: "quote", Want: quoteMinSize, Got: len(quote)}}
	}
	version := binary.LittleEndian.Uint16(quote[0:])
	keyType := binary.LittleEndian.Uint16(quote[2:])
	if version != quoteVersion || keyType != keyTypeECDSAP256 {
		return &SGXQuoteError{Op: "quote", Cause: &QuoteFormatError{Version: version, KeyType: keyType}}
	}
	at := quoteHeaderSize + reportDataOffset
	if subtle.ConstantTimeCompare(quote[at:at+reportDataSize], reportData) != 1 {
		return &SGXQuoteError{Op: "report_data", Cause: ErrReportDataMismatch}
	}
	return nil
}

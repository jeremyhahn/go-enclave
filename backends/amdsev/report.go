package amdsev

import (
	"crypto/subtle"
	"encoding/binary"
)

// ReportSize is the size of the SEV-SNP firmware's ATTESTATION_REPORT
// structure (AMD SEV Secure Nested Paging Firmware ABI, 56860), version 2
// and later, signature included.
const ReportSize = 1184

// ReportDataSize is the size of the report's REPORT_DATA field: the bytes the
// requester wrote to inblob, zero-padded by the kernel.
const ReportDataSize = 64

// Offsets of the fields ParseReport reads, from the firmware ABI's
// ATTESTATION_REPORT table. Every integer is little-endian.
const (
	offVersion    = 0x00 // VERSION, 4 bytes
	offPolicy     = 0x08 // POLICY, 8 bytes
	offVMPL       = 0x30 // VMPL, 4 bytes
	offReportData = 0x50 // REPORT_DATA, 64 bytes
)

// policyDebug is the guest POLICY bit that allows the host to debug the
// guest, reading and writing its private memory through the firmware.
const policyDebug = 1 << 19

// Report is the part of an ATTESTATION_REPORT this package reads: enough for
// the probe to check that a report answers its request. It verifies nothing:
// the signature, the certificate chain, the measurement and the TCB are the
// relying party's verifier's.
type Report struct {
	// Version is the report format's VERSION.
	Version uint32
	// Policy is the guest POLICY the guest was launched with.
	Policy uint64
	// VMPL is the VM privilege level that requested the report.
	VMPL uint32
	// ReportData is REPORT_DATA: the requester's data, zero-padded.
	ReportData [ReportDataSize]byte
}

// ParseReport reads b, which must be exactly [ReportSize] bytes, as an
// ATTESTATION_REPORT. Any other length is an [*SNPReportError] with Op
// "outblob" whose cause is a [*ReportSizeError]. The Report is a copy: it
// does not alias b.
func ParseReport(b []byte) (Report, error) {
	if len(b) != ReportSize {
		return Report{}, &SNPReportError{Op: "outblob", Cause: &ReportSizeError{Got: len(b)}}
	}
	r := Report{
		Version: binary.LittleEndian.Uint32(b[offVersion:]),
		Policy:  binary.LittleEndian.Uint64(b[offPolicy:]),
		VMPL:    binary.LittleEndian.Uint32(b[offVMPL:]),
	}
	copy(r.ReportData[:], b[offReportData:offReportData+ReportDataSize])
	return r, nil
}

// Debug reports whether the guest policy allows debugging, which lets the
// host read the guest's private memory.
func (r Report) Debug() bool { return r.Policy&policyDebug != 0 }

// HasReportData reports whether REPORT_DATA holds data zero-padded to
// [ReportDataSize] bytes, as the kernel writes it: false for empty data or
// data longer than the field. The comparison takes constant time.
func (r Report) HasReportData(data []byte) bool {
	if len(data) == 0 || len(data) > ReportDataSize {
		return false
	}
	var want [ReportDataSize]byte
	copy(want[:], data)
	return subtle.ConstantTimeCompare(r.ReportData[:], want[:]) == 1
}

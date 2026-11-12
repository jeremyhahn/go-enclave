package amdsev

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// layoutReport lays out a byte buffer as an ATTESTATION_REPORT (firmware ABI
// 56860, Table 23) with the fields the parser reads. It is input for the
// parser, not a device: nothing here stands in for configfs-tsm.
func layoutReport(version uint32, policy uint64, vmpl uint32, reportData []byte) []byte {
	b := make([]byte, ReportSize)
	binary.LittleEndian.PutUint32(b[0x00:], version)
	binary.LittleEndian.PutUint64(b[0x08:], policy)
	binary.LittleEndian.PutUint32(b[0x30:], vmpl)
	copy(b[0x50:0x90], reportData)
	return b
}

func TestParseReportSize(t *testing.T) {
	for _, n := range []int{0, 1, ReportSize - 1, ReportSize + 1, 4000} {
		_, err := ParseReport(make([]byte, n))
		var re *SNPReportError
		var se *ReportSizeError
		if !errors.As(err, &re) || re.Op != "outblob" || !errors.As(err, &se) || se.Got != n {
			t.Errorf("ParseReport(%d bytes) = %v, want *SNPReportError{Op: outblob} with *ReportSizeError{Got: %d}", n, err, n)
		}
		if !errors.Is(err, ErrSNPReport) {
			t.Errorf("ParseReport(%d bytes) does not match ErrSNPReport", n)
		}
	}
	if _, err := ParseReport(make([]byte, ReportSize)); err != nil {
		t.Errorf("ParseReport(%d bytes) = %v, want nil", ReportSize, err)
	}
}

func TestParseReportFields(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xa5}, 32)
	b := layoutReport(3, 0x30000, 1, nonce)
	r, err := ParseReport(b)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if r.Version != 3 || r.Policy != 0x30000 || r.VMPL != 1 {
		t.Errorf("ParseReport = version %d, policy %#x, vmpl %d; want 3, 0x30000, 1", r.Version, r.Policy, r.VMPL)
	}
	want := make([]byte, 64)
	copy(want, nonce)
	if !bytes.Equal(r.ReportData[:], want) {
		t.Errorf("ReportData = %x, want the nonce zero-padded to 64 bytes", r.ReportData)
	}
	if !r.HasReportData(nonce) {
		t.Errorf("HasReportData(nonce) = false, want true")
	}
	if r.HasReportData(bytes.Repeat([]byte{0x5a}, 32)) || r.HasReportData(nil) || r.HasReportData(make([]byte, 65)) {
		t.Errorf("HasReportData accepted data the report does not carry")
	}
	// The parser copies: changing the buffer leaves the report unchanged.
	b[0x50] = 0
	if r.ReportData[0] != 0xa5 {
		t.Errorf("Report aliases the buffer it was parsed from")
	}
}

func TestParseReportDebug(t *testing.T) {
	for _, tc := range []struct {
		policy uint64
		debug  bool
	}{
		{0x30000, false},
		{0x30000 | 1<<19, true},
		{1 << 19, true},
		{^uint64(0) &^ (1 << 19), false},
	} {
		r, err := ParseReport(layoutReport(2, tc.policy, 0, nil))
		if err != nil {
			t.Fatalf("ParseReport: %v", err)
		}
		if got := r.Debug(); got != tc.debug {
			t.Errorf("policy %#x: Debug() = %v, want %v", tc.policy, got, tc.debug)
		}
	}
}

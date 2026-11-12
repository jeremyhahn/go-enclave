package inteltdx

import (
	"errors"
	"testing"
	"unsafe"
)

// The request TDX_CMD_GET_REPORT0 reads and writes is struct tdx_report_req
// (include/uapi/linux/tdx-guest.h): 64 bytes of REPORTDATA, then the
// 1024-byte TDREPORT.
func TestReportRequestLayout(t *testing.T) {
	var req tdxReportReq
	if got := unsafe.Sizeof(req); got != 1088 {
		t.Fatalf("sizeof(tdx_report_req) = %d, want 1088", got)
	}
	if got := unsafe.Offsetof(req.TDReport); got != 64 {
		t.Fatalf("offsetof(tdreport) = %d, want 64", got)
	}
	// _IOWR('T', 1, struct tdx_report_req).
	if tdxCmdGetReport0 != 0xc4405401 {
		t.Fatalf("TDX_CMD_GET_REPORT0 = %#x, want 0xc4405401", uint64(tdxCmdGetReport0))
	}
}

// A TDREPORT is REPORTMACSTRUCT (256 bytes), TEE_TCB_INFO (239), 17 reserved
// bytes, then TDINFO_STRUCT, whose first field is the 8-byte little-endian
// ATTRIBUTES; bit 0 is DEBUG. The buffers are laid out by hand: a test of
// the parser, not a device.
func TestDebugTD(t *testing.T) {
	var report [tdReportSize]byte
	if debugTD(&report) {
		t.Fatal("a zero TDREPORT reads as DEBUG")
	}
	report[512] = 0x01
	if !debugTD(&report) {
		t.Fatal("ATTRIBUTES bit 0 set does not read as DEBUG")
	}
	report[512] = 0xfe
	report[519] = 0xff
	if debugTD(&report) {
		t.Fatal("ATTRIBUTES without bit 0 reads as DEBUG")
	}
	report[512] = 0
	report[511] = 0x01 // the last reserved byte before TDINFO_STRUCT
	report[520] = 0x01 // XFAM's first byte
	if debugTD(&report) {
		t.Fatal("a byte outside ATTRIBUTES reads as DEBUG")
	}
}

func TestCheckProvider(t *testing.T) {
	for _, ok := range []string{"tdx_guest", "tdx_guest\n"} {
		if err := checkProvider([]byte(ok)); err != nil {
			t.Fatalf("checkProvider(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "\n", "sev_guest\n", "tdx_guest\n\n", "tdx_guestx"} {
		err := checkProvider([]byte(bad))
		var te *TSMReportError
		if !errors.As(err, &te) || te.Op != "provider" {
			t.Fatalf("checkProvider(%q) = %v, want a TSMReportError at provider", bad, err)
		}
	}
}

func TestCheckGeneration(t *testing.T) {
	if err := checkGeneration([]byte("1\n"), 1); err != nil {
		t.Fatalf("checkGeneration(1, 1) = %v", err)
	}
	for _, moved := range []string{"0\n", "2\n", "3"} {
		err := checkGeneration([]byte(moved), 1)
		var te *TSMReportError
		if !errors.As(err, &te) || te.Op != "generation" || !errors.Is(err, ErrTSMReportConflict) {
			t.Fatalf("checkGeneration(%q) = %v, want ErrTSMReportConflict", moved, err)
		}
	}
	for _, junk := range []string{"", "x\n", "-1\n"} {
		err := checkGeneration([]byte(junk), 1)
		var te *TSMReportError
		if !errors.As(err, &te) || te.Op != "generation" || errors.Is(err, ErrTSMReportConflict) {
			t.Fatalf("checkGeneration(%q) = %v, want a parse failure at generation", junk, err)
		}
	}
}

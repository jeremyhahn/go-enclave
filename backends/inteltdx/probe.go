package inteltdx

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unsafe"
)

// The kernel interfaces the backend reaches, as docs/backends/intel-tdx.md
// "Hardware, firmware and kernel requirements" lists them.
const (
	// guestDevice is the TDX guest driver's misc device (Linux 6.2).
	guestDevice = "/dev/tdx_guest"
	// tsmReportRoot is the configfs-tsm report tree (Linux 6.7).
	tsmReportRoot = "/sys/kernel/config/tsm/report"
	// tsmProvider is the provider a TD's report directory names; it is also
	// the name of outblob's format.
	tsmProvider = "tdx_guest"
)

// The TDREPORT layout (Intel TDX Module ABI, TDREPORT_STRUCT): REPORTMACSTRUCT
// (256 bytes), TEE_TCB_INFO (239), 17 reserved bytes, then TDINFO_STRUCT,
// whose first field is the 8-byte little-endian ATTRIBUTES. Bit 0 of
// ATTRIBUTES is DEBUG (TUD.DEBUG).
const (
	reportDataSize  = 64
	tdReportSize    = 1024
	tdInfoOffset    = 256 + 239 + 17
	attributesDebug = 1 << 0
)

// tdxReportReq is struct tdx_report_req (include/uapi/linux/tdx-guest.h):
// the REPORTDATA the caller supplies and the TDREPORT the TDX module returns.
type tdxReportReq struct {
	ReportData [reportDataSize]byte
	TDReport   [tdReportSize]byte
}

// The asm-generic ioctl encoding (include/uapi/asm-generic/ioctl.h), which
// amd64 uses: direction, size, type, number.
const (
	iocNRShift   = 0
	iocTypeShift = 8
	iocSizeShift = 16
	iocDirShift  = 30

	iocWrite = 1
	iocRead  = 2
)

// tdxCmdGetReport0 is TDX_CMD_GET_REPORT0, _IOWR('T', 1, struct tdx_report_req).
const tdxCmdGetReport0 = (iocRead|iocWrite)<<iocDirShift | unsafe.Sizeof(tdxReportReq{})<<iocSizeShift | 'T'<<iocTypeShift | 1<<iocNRShift

// debugTD reports whether a TDREPORT's ATTRIBUTES has DEBUG set. It is the one
// field the backend reads from a report (docs/backends/intel-tdx.md,
// "Attestation").
func debugTD(report *[tdReportSize]byte) bool {
	return binary.LittleEndian.Uint64(report[tdInfoOffset:tdInfoOffset+8])&attributesDebug != 0
}

// checkProvider accepts a report directory whose provider attribute reads
// tdx_guest, with or without the kernel's one trailing newline.
func checkProvider(raw []byte) error {
	if got := strings.TrimSuffix(string(raw), "\n"); got != tsmProvider {
		return &TSMReportError{Op: "provider", Cause: fmt.Errorf("provider %q, want %q", got, tsmProvider)}
	}
	return nil
}

// checkGeneration accepts a report directory whose generation attribute
// counts exactly want writes: this call's own. A larger or smaller count is
// [ErrTSMReportConflict]; text that is not a count is the parse error.
func checkGeneration(raw []byte, want uint64) error {
	got, err := strconv.ParseUint(strings.TrimSuffix(string(raw), "\n"), 10, 64)
	if err != nil {
		return &TSMReportError{Op: "generation", Cause: err}
	}
	if got != want {
		return &TSMReportError{Op: "generation", Cause: ErrTSMReportConflict}
	}
	return nil
}

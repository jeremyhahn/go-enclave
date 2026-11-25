package amdsev

import (
	"encoding/binary"
	"errors"
	"math"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// devicePath is the SEV-SNP guest driver's device (CONFIG_SEV_GUEST). The
	// driver binds only when SNP is active.
	devicePath = "/dev/sev-guest"
	// tsmRoot is the configfs-tsm report directory (CONFIG_TSM_REPORTS).
	tsmRoot = "/sys/kernel/config/tsm/report"
	// sevGuestProvider is the provider an SEV-SNP guest's report entry names.
	sevGuestProvider = "sev_guest"
	// attestationReportSize is the size of an SNP ATTESTATION_REPORT.
	attestationReportSize = 1184
	// reportVMPL is the VMPL the report is requested at. 3 is the least
	// privileged level, so the firmware accepts it whatever level the guest
	// kernel runs at.
	reportVMPL = 3
	// reportOffset is where MSG_REPORT_RSP carries the ATTESTATION_REPORT,
	// after its status, report size and reserved bytes.
	reportOffset = 0x20
	// policyOffset is the offset of the 64-bit POLICY field in the
	// ATTESTATION_REPORT.
	policyOffset = 0x08
	// policyDebug is the POLICY DEBUG bit. A guest launched with it allows
	// the host to debug it, which decrypts its memory.
	policyDebug = 1 << 19
	// reportDataSize is the size of the REPORT_DATA a report request
	// carries, and of the configfs-tsm inblob.
	reportDataSize = 64
	// opOpen is the open step's name in a GuestError and an os.PathError.
	opOpen = "open"
)

// reportRequest is the kernel's struct snp_report_req.
type reportRequest struct {
	userData [reportDataSize]byte
	vmpl     uint32
	reserved [28]byte
}

// reportResponse is the kernel's struct snp_report_resp. It opens with the
// firmware's MSG_REPORT_RSP: a 32-bit status and a 32-bit report size, both
// little-endian, then the report at reportOffset.
type reportResponse struct {
	data [4000]byte
}

// guestOS is the seam between detection and the kernel. Each field is one
// call; tests replace them to drive every branch without the device. A
// guestOS with a nil openDevice is a platform with no SEV-SNP guest driver.
type guestOS struct {
	openDevice  func(path string) (int, error)
	getReport   func(fd int, req *reportRequest, resp *reportResponse) error
	closeDevice func(fd int) error
	mkdir       func(path string) error
	readFile    func(path string) ([]byte, error)
	writeFile   func(path string, data []byte) error
	rmdir       func(path string) error
	entryName   func() string
}

// detect proves that this process runs inside an SEV-SNP guest that the host
// cannot debug: the guest device returns an attestation report, or else a
// configfs-tsm report entry names the sev_guest provider and returns one, and
// the report's POLICY has DEBUG clear. It returns nil or a *GuestError.
func (g guestOS) detect(device, root string) error {
	if g.openDevice == nil {
		return &GuestError{Op: "platform", Cause: errors.ErrUnsupported}
	}
	devErr := g.deviceReport(device)
	if devErr == nil {
		return nil
	}
	if errors.Is(devErr.Cause, ErrDebugPolicy) {
		// The firmware vouched for the policy; another path would return
		// the same report.
		return devErr
	}
	tsmErr := g.tsmReport(root)
	if tsmErr == nil {
		return nil
	}
	devErr.Next = tsmErr
	return devErr
}

// deviceReport asks the guest device for an attestation report, checks that
// the firmware answered with one and checks its policy.
func (g guestOS) deviceReport(path string) *GuestError {
	fd, err := g.openDevice(path)
	if err != nil {
		return &GuestError{Path: path, Op: opOpen, Cause: err}
	}
	defer func() { _ = g.closeDevice(fd) }()
	req := &reportRequest{vmpl: reportVMPL}
	resp := &reportResponse{}
	if err := g.getReport(fd, req, resp); err != nil {
		return &GuestError{Path: path, Op: "report", Cause: err}
	}
	status := binary.LittleEndian.Uint32(resp.data[0:4])
	size := binary.LittleEndian.Uint32(resp.data[4:8])
	if status != 0 || size != attestationReportSize {
		return &GuestError{Path: path, Op: "report", Cause: &ReportError{Status: status, Size: size}}
	}
	return checkPolicy(resp.data[reportOffset:reportOffset+attestationReportSize], path)
}

// tsmReport creates a configfs-tsm report entry, has it produce a report,
// removes the entry again and returns the first failure.
func (g guestOS) tsmReport(root string) *GuestError {
	entry := filepath.Join(root, g.entryName())
	if err := g.mkdir(entry); err != nil {
		return &GuestError{Path: entry, Op: "mkdir", Cause: err}
	}
	reportErr := g.tsmEntryReport(entry)
	rmErr := g.rmdir(entry)
	if reportErr != nil {
		return reportErr
	}
	if rmErr != nil {
		return &GuestError{Path: entry, Op: "rmdir", Cause: rmErr}
	}
	return nil
}

// tsmEntryReport checks that entry's provider is sev_guest, requests a
// report at reportVMPL through it and checks the report's policy.
func (g guestOS) tsmEntryReport(entry string) *GuestError {
	providerPath := filepath.Join(entry, "provider")
	data, err := g.readFile(providerPath)
	if err != nil {
		return &GuestError{Path: providerPath, Op: "provider", Cause: err}
	}
	if p := strings.TrimSpace(string(data)); p != sevGuestProvider {
		return &GuestError{Path: providerPath, Op: "provider", Cause: &ProviderError{Provider: p}}
	}
	privPath := filepath.Join(entry, "privlevel")
	if err := g.writeFile(privPath, []byte(strconv.Itoa(reportVMPL)+"\n")); err != nil {
		return &GuestError{Path: privPath, Op: "privlevel", Cause: err}
	}
	inPath := filepath.Join(entry, "inblob")
	if err := g.writeFile(inPath, make([]byte, reportDataSize)); err != nil {
		return &GuestError{Path: inPath, Op: "inblob", Cause: err}
	}
	outPath := filepath.Join(entry, "outblob")
	report, err := g.readFile(outPath)
	if err != nil {
		return &GuestError{Path: outPath, Op: "outblob", Cause: err}
	}
	if len(report) != attestationReportSize {
		return &GuestError{Path: outPath, Op: "outblob", Cause: &ReportError{Size: reportSize(len(report))}}
	}
	return checkPolicy(report, outPath)
}

// checkPolicy refuses a report whose POLICY has the DEBUG bit set. report is
// an ATTESTATION_REPORT of attestationReportSize bytes read from path.
func checkPolicy(report []byte, path string) *GuestError {
	policy := binary.LittleEndian.Uint64(report[policyOffset : policyOffset+8])
	if policy&policyDebug != 0 {
		return &GuestError{Path: path, Op: "policy", Cause: &PolicyError{Policy: policy}}
	}
	return nil
}

// reportSize is n as a ReportError size, saturated at the largest uint32.
func reportSize(n int) uint32 {
	if n < 0 || uint64(n) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}

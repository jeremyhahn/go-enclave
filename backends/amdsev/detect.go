package amdsev

import (
	"encoding/binary"
	"errors"
	"path/filepath"
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
)

// reportRequest is the kernel's struct snp_report_req.
type reportRequest struct {
	userData [64]byte
	vmpl     uint32
	reserved [28]byte
}

// reportResponse is the kernel's struct snp_report_resp. It opens with the
// firmware's MSG_REPORT_RSP: a 32-bit status and a 32-bit report size, both
// little-endian.
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
	rmdir       func(path string) error
	entryName   func() string
}

// detect proves that this process runs inside an SEV-SNP guest: the guest
// device answers a report request, or else a configfs-tsm report entry names
// the sev_guest provider. It returns nil or a *GuestError.
func (g guestOS) detect(device, root string) error {
	if g.openDevice == nil {
		return &GuestError{Op: "platform", Cause: errors.ErrUnsupported}
	}
	devErr := g.deviceReport(device)
	if devErr == nil {
		return nil
	}
	tsmErr := g.tsmProvider(root)
	if tsmErr == nil {
		return nil
	}
	devErr.Next = tsmErr
	return devErr
}

// deviceReport asks the guest device for an attestation report and checks
// that the firmware answered with one.
func (g guestOS) deviceReport(path string) *GuestError {
	fd, err := g.openDevice(path)
	if err != nil {
		return &GuestError{Path: path, Op: "open", Cause: err}
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
	return nil
}

// tsmProvider creates a configfs-tsm report entry, reads its provider and
// removes the entry again.
func (g guestOS) tsmProvider(root string) *GuestError {
	entry := filepath.Join(root, g.entryName())
	if err := g.mkdir(entry); err != nil {
		return &GuestError{Path: entry, Op: "mkdir", Cause: err}
	}
	providerPath := filepath.Join(entry, "provider")
	data, readErr := g.readFile(providerPath)
	rmErr := g.rmdir(entry)
	if readErr != nil {
		return &GuestError{Path: providerPath, Op: "provider", Cause: readErr}
	}
	if p := strings.TrimSpace(string(data)); p != sevGuestProvider {
		return &GuestError{Path: providerPath, Op: "provider", Cause: &ProviderError{Provider: p}}
	}
	if rmErr != nil {
		return &GuestError{Path: entry, Op: "rmdir", Cause: rmErr}
	}
	return nil
}

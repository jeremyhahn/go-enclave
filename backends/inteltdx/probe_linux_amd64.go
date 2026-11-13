package inteltdx

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// errEmptyQuote is a [TSMReportError]'s Cause when outblob reads empty.
var errEmptyQuote = errors.New("outblob is empty")

// probe is the intel-tdx proposal's recommended probe (its Q3): TDREPORT,
// DEBUG bit and one quote. It checks ctx, gets a TDREPORT through
// /dev/tdx_guest over a fresh probe nonce, refuses a DEBUG TD, then produces
// one quote over the same REPORTDATA through configfs-tsm and discards it, so
// a TD whose host has no quote service is passed over.
func probe(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var req tdxReportReq
	_, _ = rand.Read(req.ReportData[:]) // crypto/rand.Read never fails
	if err := getReport(&req); err != nil {
		return err
	}
	if debugTD(&req.TDReport) {
		return ErrDebugTD
	}
	_, err := quote(ctx, req.ReportData)
	return err
}

// getReport fills req.TDReport with TDX_CMD_GET_REPORT0 over req.ReportData.
func getReport(req *tdxReportReq) error {
	f, err := os.OpenFile(guestDevice, os.O_RDWR, 0)
	if err != nil {
		return &GuestDeviceError{Op: "open", Cause: err}
	}
	rc, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return &GuestDeviceError{Op: opGetReport, Cause: err}
	}
	var errno syscall.Errno
	if err := rc.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, tdxCmdGetReport0, uintptr(unsafe.Pointer(req))) //nolint:gosec // req is the ioctl's struct tdx_report_req
	}); err != nil {
		_ = f.Close()
		return &GuestDeviceError{Op: opGetReport, Cause: err}
	}
	if errno != 0 {
		_ = f.Close()
		return &GuestDeviceError{Op: opGetReport, Cause: os.NewSyscallError("ioctl", errno)}
	}
	if err := f.Close(); err != nil {
		return &GuestDeviceError{Op: "close", Cause: err}
	}
	return nil
}

// quote returns one quote over reportData. ctx bounds the wait for the host's
// quote service, which Q3 leaves to the implementing slice: the report runs
// on its own goroutine, and when ctx ends first quote returns ctx's error
// while that goroutine finishes the kernel's read and removes its report
// directory alone.
func quote(ctx context.Context, reportData [reportDataSize]byte) ([]byte, error) {
	type result struct {
		quote []byte
		err   error
	}
	done := make(chan result, 1)
	go func() {
		q, err := tsmReport(&reportData)
		done <- result{quote: q, err: err}
	}()
	select {
	case r := <-done:
		return r.quote, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// tsmReport makes a fresh report directory, so concurrent calls never share
// an inblob, checks its provider, writes the 64 bytes of REPORTDATA, reads
// the quote from outblob, checks generation counts exactly that one write,
// and removes the directory on every path.
func tsmReport(reportData *[reportDataSize]byte) (quote []byte, err error) {
	if _, serr := os.Stat(tsmReportRoot); serr != nil {
		return nil, &TSMReportError{Op: "stat", Cause: serr}
	}
	dir, err := os.MkdirTemp(tsmReportRoot, "go-enclave-")
	if err != nil {
		return nil, &TSMReportError{Op: "mkdir", Cause: err}
	}
	defer func() {
		if rerr := os.Remove(dir); rerr != nil && err == nil {
			quote, err = nil, &TSMReportError{Op: "rmdir", Cause: rerr}
		}
	}()
	provider, err := os.ReadFile(filepath.Join(dir, "provider")) //nolint:gosec // under the report directory this call made
	if err != nil {
		return nil, &TSMReportError{Op: "provider", Cause: err}
	}
	if err = checkProvider(provider); err != nil {
		return nil, err
	}
	if err = writeAttr(filepath.Join(dir, "inblob"), reportData[:]); err != nil {
		return nil, &TSMReportError{Op: "inblob", Cause: err}
	}
	q, err := os.ReadFile(filepath.Join(dir, "outblob")) //nolint:gosec // under the report directory this call made
	if err != nil {
		return nil, &TSMReportError{Op: "outblob", Cause: err}
	}
	if len(q) == 0 {
		return nil, &TSMReportError{Op: "outblob", Cause: errEmptyQuote}
	}
	gen, err := os.ReadFile(filepath.Join(dir, "generation")) //nolint:gosec // under the report directory this call made
	if err != nil {
		return nil, &TSMReportError{Op: opGeneration, Cause: err}
	}
	if err = checkGeneration(gen); err != nil {
		return nil, err
	}
	return q, nil
}

// writeAttr writes b to a configfs attribute in one write. A binary attribute
// takes the buffer at close, so the close error is the write's.
func writeAttr(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // under the report directory this call made
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

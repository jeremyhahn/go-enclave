//go:build linux && amd64

package amdsev

import (
	"context"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// snpGetDerivedKey is SNP_GET_DERIVED_KEY:
// _IOWR('S', 0x1, struct snp_guest_request_ioctl).
const snpGetDerivedKey = 0xc0205301

// guestRequestVersion is the message version of every guest request.
const guestRequestVersion = 1

// guestRequest is struct snp_guest_request_ioctl: the message version, the
// request and response buffers' addresses, and exitinfo2, which the driver
// fills with the firmware's and the hypervisor's error words.
type guestRequest struct {
	msgVersion uint8
	_          [7]byte
	reqData    uint64
	respData   uint64
	exitInfo2  uint64
}

// deriveKey asks the firmware, through device, for the key r selects and
// writes it into dst, which is [derivedKeySize] bytes. A missing or refused
// device is an [*SNPGuestError] with Op "open"; a refused request an
// [*SNPReportError] with Op "derived-key" and a [*FirmwareError] cause. A
// refused call writes nothing into dst, and the response buffer is wiped.
func deriveKey(ctx context.Context, device string, r keyRequest, dst []byte) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	f, err := os.OpenFile(device, os.O_RDWR, 0) //nolint:gosec // G304: the fixed guest device path
	if err != nil {
		return guestError("open", err)
	}
	defer f.Close()

	req := new([keyRequestSize]byte)
	*req = r.encode()
	resp := new([keyResponseSize]byte)
	defer clear(resp[:])
	var pin runtime.Pinner
	pin.Pin(req)
	pin.Pin(resp)
	defer pin.Unpin()
	g := guestRequest{
		msgVersion: guestRequestVersion,
		reqData:    uint64(uintptr(unsafe.Pointer(req))),  //nolint:gosec // G103: the driver reads the pinned request
		respData:   uint64(uintptr(unsafe.Pointer(resp))), //nolint:gosec // G103: the driver writes the pinned response
	}

	conn, err := f.SyscallConn()
	if err != nil {
		return reportError("derived-key", err)
	}
	var errno unix.Errno
	if err := conn.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, snpGetDerivedKey,
			uintptr(unsafe.Pointer(&g))) //nolint:gosec // G103: the ioctl's argument struct
	}); err != nil {
		return reportError("derived-key", err)
	}
	if errno != 0 {
		return reportError("derived-key", firmwareError(g.exitInfo2, os.NewSyscallError("ioctl", errno)))
	}
	if err := ctxErr(ctx); err != nil {
		return err
	}
	if err := decodeKeyResponse(resp, dst); err != nil {
		return reportError("derived-key", err)
	}
	return nil
}

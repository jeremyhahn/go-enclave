package confidentialvm

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

// openDevice opens and closes device, so a missing or refused device fails
// construction as a *DerivedKeyError with Op "open".
func openDevice(device string) error {
	f, err := os.OpenFile(device, os.O_RDWR, 0) //nolint:gosec // G304: the fixed guest device path
	if err != nil {
		return &DerivedKeyError{Op: "open", Cause: err}
	}
	return f.Close()
}

// deriveKey asks the firmware, through device, for the key r selects and
// writes it into dst, which is [derivedKeySize] bytes. A missing or refused
// device is a *DerivedKeyError with Op "open"; a refused request one with Op
// "derived-key" and a *FirmwareError cause. A refused call writes nothing
// into dst, and the response buffer is wiped.
func deriveKey(ctx context.Context, device string, r keyRequest, dst []byte) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}
	f, err := os.OpenFile(device, os.O_RDWR, 0) //nolint:gosec // G304: the fixed guest device path
	if err != nil {
		return &DerivedKeyError{Op: "open", Cause: err}
	}
	defer f.Close()

	req := new([keyRequestSize]byte)
	*req = r.encode()
	var pin runtime.Pinner
	pin.Pin(req)
	defer pin.Unpin()

	conn, err := f.SyscallConn()
	if err != nil {
		return &DerivedKeyError{Op: "derived-key", Cause: err}
	}
	// The response, which carries the derived key, lands in locked memory
	// outside the Go heap, so it needs no pin.
	return receiveKey(dst, func(resp *[keyResponseSize]byte) error {
		g := guestRequest{
			msgVersion: guestRequestVersion,
			reqData:    uint64(uintptr(unsafe.Pointer(req))),  //nolint:gosec // G103: the driver reads the pinned request
			respData:   uint64(uintptr(unsafe.Pointer(resp))), //nolint:gosec // G103: the driver writes the locked response
		}
		var errno unix.Errno
		if err := conn.Control(func(fd uintptr) {
			_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, snpGetDerivedKey,
				uintptr(unsafe.Pointer(&g))) //nolint:gosec // G103: the ioctl's argument struct
		}); err != nil {
			return &DerivedKeyError{Op: "derived-key", Cause: err}
		}
		if errno != 0 {
			return &DerivedKeyError{Op: "derived-key", Cause: firmwareError(g.exitInfo2, os.NewSyscallError("ioctl", errno))}
		}
		return ctxErr(ctx)
	})
}

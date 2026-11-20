//go:build linux

package amdsev

import (
	"crypto/rand"
	"os"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// snpGetReport is SNP_GET_REPORT: _IOWR('S', 0x0, struct
// snp_guest_request_ioctl), a 32-byte argument.
const snpGetReport = 0xC0205300

// guestRequest is the kernel's struct snp_guest_request_ioctl.
type guestRequest struct {
	msgVersion uint8
	_          [7]byte
	reqData    uint64
	respData   uint64
	exitInfo2  uint64
}

// hostOS is the kernel behind the seam.
func hostOS() guestOS {
	return guestOS{
		openDevice:  openDevice,
		getReport:   getReport,
		closeDevice: unix.Close,
		mkdir:       func(path string) error { return os.Mkdir(path, 0o700) },
		readFile:    os.ReadFile,
		rmdir:       os.Remove,
		entryName:   entryName,
	}
}

// openDevice opens the guest device read-write, as its ioctls require.
func openDevice(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return fd, nil
}

// getReport issues SNP_GET_REPORT on fd. The request and response are Go
// memory the kernel reads and writes during the call; the collector does not
// move heap objects, and KeepAlive holds them until the call returns.
func getReport(fd int, req *reportRequest, resp *reportResponse) error {
	ioc := guestRequest{
		msgVersion: 1,
		reqData:    uint64(uintptr(unsafe.Pointer(req))),  //nolint:gosec // the kernel ABI takes the address as a u64
		respData:   uint64(uintptr(unsafe.Pointer(resp))), //nolint:gosec // the kernel ABI takes the address as a u64
	}
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), snpGetReport, uintptr(unsafe.Pointer(&ioc))) //nolint:gosec // ioctl argument
	runtime.KeepAlive(req)
	runtime.KeepAlive(resp)
	runtime.KeepAlive(&ioc)
	if errno != 0 {
		return os.NewSyscallError("ioctl SNP_GET_REPORT", errno)
	}
	return nil
}

// entryName is a configfs-tsm entry name no other caller picks.
func entryName() string {
	return "go-enclave-amdsev-" + strconv.Itoa(os.Getpid()) + "-" + rand.Text()
}

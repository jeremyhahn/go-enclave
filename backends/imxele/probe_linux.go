//go:build linux

package imxele

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// probeDevice opens the TEE device, checks TEE_IOC_VERSION, and closes it.
// The ioctl ABI is the same on every Linux architecture, so the path is
// tried for real everywhere; a host without the device refuses at "open".
func probeDevice(path string) (err error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return &TEEDeviceError{Path: path, Op: "open", Cause: os.NewSyscallError("open", err)}
	}
	defer func() {
		if cerr := unix.Close(fd); cerr != nil && err == nil {
			err = &TEEDeviceError{Path: path, Op: "close", Cause: os.NewSyscallError("close", cerr)}
		}
	}()

	var buf [teeVersionSize]byte
	//nolint:gosec // the TEE ioctl ABI passes the buffer's address to the kernel; fd is a valid descriptor
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), teeIOCVersion, uintptr(unsafe.Pointer(&buf[0]))); errno != 0 {
		return &TEEDeviceError{Path: path, Op: "version", Cause: os.NewSyscallError("ioctl", errno)}
	}
	v, err := parseVersion(buf[:])
	if err != nil {
		return &TEEDeviceError{Path: path, Op: "version", Cause: err}
	}
	if err := checkVersion(v); err != nil {
		return &TEEDeviceError{Path: path, Op: "version", Cause: err}
	}
	return nil
}

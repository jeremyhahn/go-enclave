//go:build linux

package nvblackwell

import (
	"os"

	"golang.org/x/sys/unix"
)

// probeHost reads the NVIDIA driver's procfs entry and checks it names the
// open kernel module. Each failing step is a [*DriverError] wrapping the
// call's errno.
func probeHost() error {
	buf, op, err := readDriverVersion()
	if err != nil {
		return &DriverError{Path: driverVersionPath, Op: op, Cause: err}
	}
	return checkDriverVersion(buf)
}

// readDriverVersion reads at most driverVersionMax bytes of the procfs entry.
// It returns the failing step and its *os.SyscallError on error.
func readDriverVersion() ([]byte, string, error) {
	var fd int
	var err error
	for {
		fd, err = unix.Open(driverVersionPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		return nil, "open", os.NewSyscallError("open", err)
	}
	defer func() { _ = unix.Close(fd) }()
	buf := make([]byte, driverVersionMax)
	off := 0
	for off < len(buf) {
		n, err := unix.Read(fd, buf[off:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, "read", os.NewSyscallError("read", err)
		}
		if n == 0 {
			break
		}
		off += n
	}
	return buf[:off], "", nil
}

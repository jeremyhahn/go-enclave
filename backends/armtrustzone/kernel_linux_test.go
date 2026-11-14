package armtrustzone

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openFDs counts the entries in /proc/self/fd.
func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(ents)
}

func TestKernelOpenMissingPath(t *testing.T) {
	fd, err := kernel{}.open(filepath.Join(t.TempDir(), "tee0"))
	if !errors.Is(err, unix.ENOENT) {
		t.Fatalf("open = %d, %v; want ENOENT", fd, err)
	}
}

func TestIoctlRetOnANonTEEFD(t *testing.T) {
	null, err := kernel{}.open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = unix.Close(null) })

	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) })

	closed, err := unix.Open(os.DevNull, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	if err := unix.Close(closed); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, tc := range []struct {
		name string
		fd   int
		want unix.Errno
	}{
		{"dev-null", null, unix.ENOTTY},
		{"pipe", p[0], unix.ENOTTY},
		{"closed", closed, unix.EBADF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v teeVersionData
			r, err := ioctlRet(tc.fd, teeIOCVersion, unsafe.Pointer(&v))
			if r != -1 || !errors.Is(err, tc.want) {
				t.Fatalf("ioctlRet = %d, %v; want -1, %v", r, err, tc.want)
			}
		})
	}
}

func TestKernelDriverOnDevNull(t *testing.T) {
	fd, err := kernel{}.open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })

	var v teeVersionData
	if r, err := (kernel{}).ioctl(fd, teeIOCVersion, unsafe.Pointer(&v)); r != -1 || !errors.Is(err, unix.ENOTTY) {
		t.Errorf("ioctl = %d, %v; want -1, ENOTTY", r, err)
	}
	var buf teeOpenSessionBuf
	if err := (kernel{}).ioctlBuf(fd, teeIOCOpenSession, unsafe.Pointer(&buf), unsafe.Sizeof(buf)); !errors.Is(err, unix.ENOTTY) {
		t.Errorf("ioctlBuf = %v; want ENOTTY", err)
	}
	shmFD, id, err := kernel{}.registerShm(fd, make([]byte, 64))
	if shmFD != -1 || id != 0 || !errors.Is(err, unix.ENOTTY) {
		t.Errorf("registerShm = %d, %d, %v; want -1, 0, ENOTTY", shmFD, id, err)
	}
}

func TestKernelMmapRoundTrip(t *testing.T) {
	fd, err := unix.MemfdCreate("armtrustzone-test", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatalf("memfd_create: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	size := os.Getpagesize()
	if err := unix.Ftruncate(fd, int64(size)); err != nil {
		t.Fatalf("ftruncate: %v", err)
	}

	b, err := kernel{}.mmap(fd, size)
	if err != nil {
		t.Fatalf("mmap: %v", err)
	}
	if len(b) != size {
		t.Fatalf("mmap len = %d; want %d", len(b), size)
	}
	b[0], b[size-1] = 0xa5, 0x5a
	if err := (kernel{}).munmap(b); err != nil {
		t.Fatalf("munmap: %v", err)
	}

	got := make([]byte, size)
	if n, err := unix.Pread(fd, got, 0); err != nil || n != size {
		t.Fatalf("pread = %d, %v", n, err)
	}
	if got[0] != 0xa5 || got[size-1] != 0x5a {
		t.Fatalf("memfd holds %#x..%#x; want 0xa5..0x5a", got[0], got[size-1])
	}
}

func TestKernelCloseTwice(t *testing.T) {
	fd, err := kernel{}.open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	if err := (kernel{}).close(fd); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := (kernel{}).close(fd); !errors.Is(err, unix.EBADF) {
		t.Fatalf("second close = %v; want EBADF", err)
	}
}

func TestOpenClientOnANonTEEDevice(t *testing.T) {
	_ = openFDs(t) // let the runtime open what it opens lazily
	before := openFDs(t)

	c, err := openClient(os.DevNull, teecUUID{})
	if c != nil {
		t.Fatalf("openClient returned a client on %s", os.DevNull)
	}
	var de *DeviceError
	if !errors.As(err, &de) {
		t.Fatalf("openClient = %v; want a *DeviceError", err)
	}
	if de.Op != "version" || de.Endpoint != os.DevNull {
		t.Errorf("DeviceError = %+v; want Op version on %s", de, os.DevNull)
	}
	if !errors.Is(err, unix.ENOTTY) {
		t.Errorf("openClient = %v; want ENOTTY", err)
	}
	if after := openFDs(t); after != before {
		t.Errorf("open fds %d before, %d after: openClient leaked its fd", before, after)
	}
}

func TestDeviceErrorFillsOpAndCause(t *testing.T) {
	c := &client{endpoint: "/dev/tee9"}
	err := c.deviceError("invoke", unix.EIO)
	var de *DeviceError
	if !errors.As(err, &de) {
		t.Fatalf("deviceError = %T; want *DeviceError", err)
	}
	if de.Endpoint != "/dev/tee9" || de.Op != "invoke" {
		t.Errorf("DeviceError = %+v; want invoke on /dev/tee9", de)
	}
	var se *os.SyscallError
	if !errors.As(de.Cause, &se) || se.Syscall != "ioctl" || !errors.Is(se.Err, unix.EIO) {
		t.Errorf("Cause = %v; want ioctl: EIO", de.Cause)
	}
}

// stubDriver answers the version and open-session ioctls as told and
// records which fds were closed.
type stubDriver struct {
	genCaps    uint32
	sessionErr error
	ret        uint32
	devFD      int
	closed     map[int]bool
}

func newStubDriver(genCaps uint32) *stubDriver {
	return &stubDriver{genCaps: genCaps, devFD: 7, closed: map[int]bool{}}
}

func (d *stubDriver) open(string) (int, error) { return d.devFD, nil }

func (d *stubDriver) ioctl(_ int, req uintptr, arg unsafe.Pointer) (int, error) {
	if req != teeIOCVersion {
		return -1, unix.ENOTTY
	}
	(*teeVersionData)(arg).GenCaps = d.genCaps
	return 0, nil
}

func (d *stubDriver) ioctlBuf(_ int, req uintptr, p unsafe.Pointer, _ uintptr) error {
	if req != teeIOCOpenSession {
		return unix.ENOTTY
	}
	if d.sessionErr != nil {
		return d.sessionErr
	}
	(*teeOpenSessionBuf)(p).Arg.Ret = d.ret
	return nil
}

func (d *stubDriver) registerShm(int, []byte) (int, int32, error) { return -1, 0, unix.ENOTTY }
func (d *stubDriver) mmap(int, int) ([]byte, error)               { return nil, unix.ENOTTY }
func (d *stubDriver) munmap([]byte) error                         { return nil }

func (d *stubDriver) close(fd int) error {
	if d.closed[fd] {
		return unix.EBADF
	}
	d.closed[fd] = true
	return nil
}

func TestOpenClientOnRefusals(t *testing.T) {
	const endpoint = "/dev/tee0"
	t.Run("not-global-platform", func(t *testing.T) {
		d := newStubDriver(0)
		_, err := openClientOn(d, endpoint, teecUUID{})
		var de *DeviceError
		if !errors.As(err, &de) || de.Op != "version" || !errors.Is(err, ErrNotGlobalPlatform) {
			t.Fatalf("openClientOn = %v; want version: ErrNotGlobalPlatform", err)
		}
		if !d.closed[d.devFD] {
			t.Error("fd not closed")
		}
	})
	t.Run("open-session-errno", func(t *testing.T) {
		d := newStubDriver(teeGenCapGP)
		d.sessionErr = unix.EINVAL
		_, err := openClientOn(d, endpoint, teecUUID{})
		var de *DeviceError
		if !errors.As(err, &de) || de.Op != "open-session" || !errors.Is(err, unix.EINVAL) {
			t.Fatalf("openClientOn = %v; want open-session: EINVAL", err)
		}
		if !d.closed[d.devFD] {
			t.Error("fd not closed")
		}
	})
	t.Run("session-refused", func(t *testing.T) {
		d := newStubDriver(teeGenCapGP)
		d.ret = fakeErrItemNotFound
		_, err := openClientOn(d, endpoint, teecUUID{})
		var se *SessionError
		if !errors.As(err, &se) || se.Code != fakeErrItemNotFound {
			t.Fatalf("openClientOn = %v; want a SessionError %#x", err, fakeErrItemNotFound)
		}
		if !d.closed[d.devFD] {
			t.Error("fd not closed")
		}
	})
}

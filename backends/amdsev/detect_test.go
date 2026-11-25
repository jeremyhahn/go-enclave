package amdsev

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

// testDebugPolicy is a guest POLICY with DEBUG (bit 19) set, beside the
// reserved bit 17 the firmware requires to be one.
const testDebugPolicy uint64 = 1<<19 | 1<<17

// fakeGuest drives detection through the seam. Each field is the error the
// matching call returns; provider is what the configfs entry names, and
// policy is the POLICY field of the report both paths return.
type fakeGuest struct {
	openErr, reportErr, mkdirErr, readErr, rmdirErr error
	writeErr                                        error
	status, size                                    uint32
	provider                                        string
	policy                                          uint64
	blobLen                                         int

	closed, removed int
	vmpl            uint32
	written         []string
}

// successGuest is an SEV-SNP guest whose device answers.
func successGuest() *fakeGuest {
	return &fakeGuest{size: attestationReportSize, provider: sevGuestProvider}
}

// report is an attestation report carrying f's policy.
func (f *fakeGuest) report() []byte {
	r := make([]byte, attestationReportSize)
	binary.LittleEndian.PutUint64(r[8:16], f.policy)
	return r
}

func (f *fakeGuest) os() guestOS {
	return guestOS{
		openDevice: func(path string) (int, error) {
			if f.openErr != nil {
				return -1, &os.PathError{Op: "open", Path: path, Err: f.openErr}
			}
			return 7, nil
		},
		getReport: func(_ int, req *reportRequest, resp *reportResponse) error {
			f.vmpl = req.vmpl
			if f.reportErr != nil {
				return os.NewSyscallError("ioctl SNP_GET_REPORT", f.reportErr)
			}
			binary.LittleEndian.PutUint32(resp.data[0:4], f.status)
			binary.LittleEndian.PutUint32(resp.data[4:8], f.size)
			copy(resp.data[32:], f.report())
			return nil
		},
		closeDevice: func(int) error { f.closed++; return nil },
		mkdir:       func(string) error { return f.mkdirErr },
		readFile: func(path string) ([]byte, error) {
			if f.readErr != nil {
				return nil, f.readErr
			}
			if filepath.Base(path) == "outblob" {
				if f.blobLen > 0 {
					return f.report()[:f.blobLen], nil
				}
				return f.report(), nil
			}
			return []byte(f.provider + "\n"), nil
		},
		writeFile: func(path string, data []byte) error {
			f.written = append(f.written, filepath.Base(path)+"="+string(data))
			return f.writeErr
		},
		rmdir:     func(string) error { f.removed++; return f.rmdirErr },
		entryName: func() string { return "entry" },
	}
}

func (f *fakeGuest) detect() error { return f.os().detect(devicePath, tsmRoot) }

func TestDetectDeviceAnswers(t *testing.T) {
	f := successGuest()
	if err := f.detect(); err != nil {
		t.Fatal(err)
	}
	if f.closed != 1 {
		t.Fatalf("device closed %d times, want 1", f.closed)
	}
	if f.vmpl != reportVMPL {
		t.Fatalf("report requested at VMPL %d, want %d", f.vmpl, reportVMPL)
	}
	if f.removed != 0 {
		t.Fatal("configfs-tsm tried after the device answered")
	}
}

func TestDetectFallsBackToTSM(t *testing.T) {
	for name, f := range map[string]*fakeGuest{
		"device absent": {openErr: syscall.ENOENT, provider: sevGuestProvider},
		"device EACCES": {openErr: syscall.EACCES, provider: sevGuestProvider},
		"ioctl fails":   {reportErr: syscall.EIO, provider: sevGuestProvider},
	} {
		t.Run(name, func(t *testing.T) {
			if err := f.detect(); err != nil {
				t.Fatal(err)
			}
			if f.removed != 1 {
				t.Fatalf("entry removed %d times, want 1", f.removed)
			}
			want := []string{"privlevel=3\n", "inblob=" + string(make([]byte, reportDataSize))}
			if !slices.Equal(f.written, want) {
				t.Fatalf("written %q, want %q", f.written, want)
			}
		})
	}
}

func TestDetectRefuses(t *testing.T) {
	cases := []struct {
		name          string
		f             *fakeGuest
		op, nextOp    string
		cause, nextIs error
	}{
		{"device absent, no configfs", &fakeGuest{openErr: syscall.ENOENT, mkdirErr: syscall.ENOENT},
			"open", "mkdir", syscall.ENOENT, syscall.ENOENT},
		{"device EACCES, configfs EACCES", &fakeGuest{openErr: syscall.EACCES, mkdirErr: syscall.EACCES},
			"open", "mkdir", syscall.EACCES, syscall.EACCES},
		{"ioctl fails, provider unreadable", &fakeGuest{reportErr: syscall.EIO, readErr: syscall.EIO},
			"report", "provider", syscall.EIO, syscall.EIO},
		{"firmware status, wrong provider", &fakeGuest{status: 0x16, size: attestationReportSize, provider: "tdx_guest"},
			"report", "provider", ErrReportRefused, ErrWrongProvider},
		{"short report, rmdir fails", &fakeGuest{size: 100, provider: sevGuestProvider, rmdirErr: syscall.EBUSY},
			"report", "rmdir", ErrReportRefused, syscall.EBUSY},
		{"device absent, privlevel refused", &fakeGuest{openErr: syscall.ENOENT, provider: sevGuestProvider, writeErr: syscall.EINVAL},
			"open", "privlevel", syscall.ENOENT, syscall.EINVAL},
		{"device absent, short outblob", &fakeGuest{openErr: syscall.ENOENT, provider: sevGuestProvider, blobLen: 100},
			"open", "outblob", syscall.ENOENT, ErrReportRefused},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.f.detect()
			if !errors.Is(err, ErrSNPGuestUnavailable) {
				t.Fatalf("err = %v, want ErrSNPGuestUnavailable", err)
			}
			var ge *GuestError
			if !errors.As(err, &ge) || ge.Op != c.op || ge.Path != devicePath {
				t.Fatalf("err = %#v, want op %q on %s", ge, c.op, devicePath)
			}
			if !errors.Is(ge.Cause, c.cause) {
				t.Fatalf("cause = %v, want %v", ge.Cause, c.cause)
			}
			var next *GuestError
			if !errors.As(ge.Next, &next) || next.Op != c.nextOp {
				t.Fatalf("next = %#v, want op %q", ge.Next, c.nextOp)
			}
			if !errors.Is(next.Cause, c.nextIs) {
				t.Fatalf("next cause = %v, want %v", next.Cause, c.nextIs)
			}
		})
	}
}

// TestDetectRefusesDebugPolicy checks that a guest launched with the POLICY
// DEBUG bit, whose memory the host can decrypt, is refused on both paths.
func TestDetectRefusesDebugPolicy(t *testing.T) {
	policyRefused := func(t *testing.T, err error, path string) {
		t.Helper()
		var ge *GuestError
		if !errors.As(err, &ge) || ge.Op != "policy" || ge.Path != path {
			t.Fatalf("err = %#v, want op policy on %s", err, path)
		}
		var pe *PolicyError
		if !errors.Is(ge.Cause, ErrDebugPolicy) || !errors.As(ge.Cause, &pe) || pe.Policy != testDebugPolicy {
			t.Fatalf("cause = %v, want a PolicyError for %#x", ge.Cause, testDebugPolicy)
		}
	}

	t.Run("device report", func(t *testing.T) {
		f := successGuest()
		f.policy = testDebugPolicy
		err := f.detect()
		if !errors.Is(err, ErrSNPGuestUnavailable) {
			t.Fatalf("err = %v, want ErrSNPGuestUnavailable", err)
		}
		policyRefused(t, err, devicePath)
		var ge *GuestError
		if errors.As(err, &ge) && ge.Next != nil {
			t.Fatalf("configfs-tsm tried after a debug report: %v", ge.Next)
		}
		if f.removed != 0 {
			t.Fatal("configfs-tsm tried after a debug report")
		}
	})

	t.Run("configfs report", func(t *testing.T) {
		f := &fakeGuest{openErr: syscall.ENOENT, provider: sevGuestProvider, policy: testDebugPolicy}
		err := f.detect()
		if !errors.Is(err, ErrSNPGuestUnavailable) {
			t.Fatalf("err = %v, want ErrSNPGuestUnavailable", err)
		}
		var ge *GuestError
		if !errors.As(err, &ge) || ge.Op != "open" {
			t.Fatalf("err = %#v, want the device's open step first", err)
		}
		policyRefused(t, ge.Next, filepath.Join(tsmRoot, "entry", "outblob"))
		if f.removed != 1 {
			t.Fatalf("entry removed %d times, want 1", f.removed)
		}
	})
}

func TestDetectNoDriverPlatform(t *testing.T) {
	err := guestOS{}.detect(devicePath, tsmRoot)
	var ge *GuestError
	if !errors.As(err, &ge) || ge.Op != "platform" || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("err = %v, want the platform step", err)
	}
}

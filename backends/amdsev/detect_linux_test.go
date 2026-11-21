//go:build linux

package amdsev

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

// TestHostOSOnFiles runs the kernel side of the seam against a regular file
// standing in for the device, which refuses the ioctl, and a directory
// standing in for configfs-tsm, whose entry has no provider.
func TestHostOSOnFiles(t *testing.T) {
	dir := t.TempDir()
	dev := dir + "/sev-guest"
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err := hostOS().detect(dev, dir)
	var ge *GuestError
	if !errors.As(err, &ge) || ge.Op != "report" || !errors.Is(ge.Cause, syscall.ENOTTY) {
		t.Fatalf("err = %v, want the report step refused with ENOTTY", err)
	}
	var next *GuestError
	if !errors.As(ge.Next, &next) || next.Op != "provider" || !errors.Is(next.Cause, syscall.ENOENT) {
		t.Fatalf("next = %v, want the provider step with ENOENT", ge.Next)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("configfs-tsm entry left behind: %d entries", len(entries))
	}
}

func TestWriteAttribute(t *testing.T) {
	path := t.TempDir() + "/inblob"
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeAttribute(path, []byte("3\n")); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "3\n" {
		t.Fatalf("attribute = %q, %v; want \"3\\n\"", got, err)
	}
	err := writeAttribute(path+"-absent", []byte("3\n"))
	var pe *os.PathError
	if !errors.As(err, &pe) || pe.Op != "open" || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("err = %v, want open refused with ENOENT", err)
	}
}

func TestHostOSDeviceAbsent(t *testing.T) {
	dir := t.TempDir()
	err := hostOS().detect(dir+"/absent", dir+"/absent")
	var ge *GuestError
	if !errors.As(err, &ge) || ge.Op != "open" || !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("err = %v, want the open step with ENOENT", err)
	}
}

func TestEntryNamesDiffer(t *testing.T) {
	if entryName() == entryName() {
		t.Fatal("two entry names are equal")
	}
}

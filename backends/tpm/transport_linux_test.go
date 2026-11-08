//go:build linux

package tpm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenDevice_RefusesPath opens paths that exist and can be read and
// written but are not TPM devices: each is refused with a DeviceError
// naming the path.
func TestOpenDevice_RefusesPath(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "tpmrm0")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)

	for name, path := range map[string]string{
		"relative":        "tpmrm0",
		"relative_dot":    "./tpmrm0",
		"regular_file":    regular,
		"unclean_regular": dir + "/../" + filepath.Base(dir) + "/tpmrm0",
		"directory":       dir,
	} {
		t.Run(name, func(t *testing.T) {
			dev, err := openDevice(path, newFakeAllocator())
			if err == nil {
				_ = dev.close()
				t.Fatalf("openDevice(%q) succeeded, want a refusal", path)
			}
			var de *DeviceError
			if !errors.As(err, &de) || !errors.Is(err, ErrDeviceUnavailable) {
				t.Fatalf("got %v, want a DeviceError", err)
			}
			if de.Path != path || de.Op != "open" || !strings.Contains(err.Error(), path) {
				t.Fatalf("got %v (path %q, op %q), want the open of %q named", err, de.Path, de.Op, path)
			}
		})
	}
}

// TestOpenDevice_CharacterDevice opens a character device that is not a
// TPM: the path checks pass it, and the transport only opens it.
func TestOpenDevice_CharacterDevice(t *testing.T) {
	dev, err := openDevice("/dev/null", newFakeAllocator())
	if err != nil {
		t.Fatalf("openDevice(/dev/null): %v", err)
	}
	if err := dev.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

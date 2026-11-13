package confidentialvm

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// notADevice is a regular file: it opens like the guest device, and the
// kernel refuses the ioctl on it with ENOTTY.
func notADevice(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sev-guest")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDeriveKey_ARefusedIoctlIsAFirmwareErrorAndWritesNothing(t *testing.T) {
	dst := bytes.Repeat([]byte{0x5a}, derivedKeySize)
	err := deriveKey(context.Background(), notADevice(t), testRequest, dst)
	de := wantDerived(t, err, "derived-key")
	var fe *FirmwareError
	if !errors.As(de, &fe) || !errors.Is(fe, unix.ENOTTY) {
		t.Fatalf("Cause = %v, want a *FirmwareError wrapping ENOTTY", de.Cause)
	}
	if !bytes.Equal(dst, bytes.Repeat([]byte{0x5a}, derivedKeySize)) {
		t.Fatalf("a refused derivation wrote %x", dst)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := deriveKey(ctx, notADevice(t), testRequest, dst); !errors.Is(err, context.Canceled) {
		t.Fatalf("deriveKey(canceled) = %v", err)
	}
}

func TestNewKeyProtector_RefusesWithoutAnSNPReport(t *testing.T) {
	useDevice(t, notADevice(t))
	useRoot(t, filepath.Join(t.TempDir(), "absent"))
	_, err := NewKeyProtector()
	de := wantDerived(t, err, "report")
	var te *TSMReportError
	if !errors.As(de, &te) || te.Op != "stat" {
		t.Fatalf("Cause = %v, want the *TSMReportError for stat", de.Cause)
	}
}

func TestOpenDevice_NamesARefusedOpen(t *testing.T) {
	if err := openDevice(notADevice(t)); err != nil {
		t.Fatal(err)
	}
	wantDerived(t, openDevice(t.TempDir()), "open")
}

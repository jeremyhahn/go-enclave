package amdsev

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
)

func TestKeyRequestEncoding(t *testing.T) {
	r := keyRequest{
		rootKey:    rootKeyVMRK,
		fields:     fieldPolicy | fieldMeasurement | fieldTCBVersion,
		vmpl:       2,
		guestSVN:   0x01020304,
		tcbVersion: 0x1122334455667788,
	}
	want := [keyRequestSize]byte{
		0x01, 0, 0, 0, // ROOT_KEY_SELECT: the VMRK
		0, 0, 0, 0, // reserved
		0x29, 0, 0, 0, 0, 0, 0, 0, // GUEST_FIELD_SELECT: policy, measurement, TCB version
		0x02, 0, 0, 0, // VMPL
		0x04, 0x03, 0x02, 0x01, // GUEST_SVN
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // TCB_VERSION
	}
	if got := r.encode(); got != want {
		t.Errorf("encode() = % x\nwant       % x", got, want)
	}
}

func TestSealKeyRequestBindsTheLaunch(t *testing.T) {
	want := keyRequest{rootKey: rootKeyVCEK, fields: fieldPolicy | fieldMeasurement}
	if sealKeyRequest != want {
		t.Errorf("sealKeyRequest = %+v, want %+v", sealKeyRequest, want)
	}
}

func TestDecodeKeyResponse(t *testing.T) {
	var resp [keyResponseSize]byte
	for i := range derivedKeySize {
		resp[keyResponseKeyOffset+i] = byte(0xa0 + i)
	}
	dst := make([]byte, derivedKeySize)
	if err := decodeKeyResponse(&resp, dst); err != nil {
		t.Fatalf("decodeKeyResponse(status 0) = %v", err)
	}
	if !bytes.Equal(dst, resp[keyResponseKeyOffset:]) {
		t.Errorf("dst = % x, want the response's DERIVED_KEY", dst)
	}
}

func TestDecodeKeyResponseRefusesAFirmwareStatus(t *testing.T) {
	var resp [keyResponseSize]byte
	resp[0] = 0x16 // STATUS: INVALID_PARAM
	for i := keyResponseKeyOffset; i < keyResponseSize; i++ {
		resp[i] = 0xff
	}
	dst := make([]byte, derivedKeySize)
	err := decodeKeyResponse(&resp, dst)
	var fe *FirmwareError
	if !errors.As(err, &fe) || fe.Status != 0x16 {
		t.Fatalf("decodeKeyResponse(status 0x16) = %v, want a *FirmwareError with Status 0x16", err)
	}
	if !bytes.Equal(dst, make([]byte, derivedKeySize)) {
		t.Errorf("a refused response wrote key material into dst")
	}
}

func TestFirmwareErrorSplitsExitInfo2(t *testing.T) {
	err := firmwareError(0x0000000200000016, syscall.EIO)
	if err.VMMError != 2 || err.FWError != 0x16 || err.Status != 0 {
		t.Errorf("firmwareError = %+v, want VMMError 2, FWError 0x16, Status 0", err)
	}
	if !errors.Is(err, syscall.EIO) {
		t.Errorf("firmwareError does not unwrap to its errno")
	}
	if err.Error() == "" {
		t.Errorf("empty message")
	}
}

// TestDeriveKeyRefusesOutsideAnSNPGuest proves the refusal on a host that is
// not an SNP guest (an SEV or SEV-ES guest, or no guest at all): there is no
// /dev/sev-guest, and the error names the step. The in-guest pass, a key
// derived twice to the same bytes and differently for another field
// selection, needs a real SNP guest and is a later slice.
func TestDeriveKeyRefusesOutsideAnSNPGuest(t *testing.T) {
	dst := make([]byte, derivedKeySize)
	err := deriveKey(context.Background(), sevGuestDevice, sealKeyRequest, dst)
	if err == nil {
		t.Skip("this host is an SNP guest: the in-guest slice covers it")
	}
	if !errors.Is(err, ErrSNPGuestUnavailable) {
		t.Fatalf("deriveKey = %v, want ErrSNPGuestUnavailable", err)
	}
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		var ge *SNPGuestError
		var pe *os.PathError
		if !errors.As(err, &ge) || ge.Op != "open" || !errors.As(err, &pe) {
			t.Errorf("deriveKey = %v, want an *SNPGuestError with Op open and an *os.PathError cause", err)
		}
	}
	if !bytes.Equal(dst, make([]byte, derivedKeySize)) {
		t.Errorf("a refused request wrote key material into dst")
	}
}

func TestDeriveKeyEndedContext(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("off Linux on amd64 the stub refuses before the context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := deriveKey(ctx, sevGuestDevice, sealKeyRequest, make([]byte, derivedKeySize)); !errors.Is(err, context.Canceled) {
		t.Errorf("deriveKey(ended ctx) = %v, want context.Canceled", err)
	}
}

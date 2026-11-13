package confidentialvm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// useDevice points sevGuestDevice at path for the test and restores it.
func useDevice(t *testing.T, path string) {
	t.Helper()
	old := sevGuestDevice
	sevGuestDevice = path
	t.Cleanup(func() { sevGuestDevice = old })
}

// wantDerived fails unless err is a *DerivedKeyError for op that matches
// ErrDerivedKeyUnavailable and not ErrSealedAuthentication.
func wantDerived(t *testing.T, err error, op string) *DerivedKeyError {
	t.Helper()
	var de *DerivedKeyError
	if !errors.As(err, &de) || de.Op != op || !errors.Is(err, ErrDerivedKeyUnavailable) ||
		errors.Is(err, enclave.ErrSealedAuthentication) {
		t.Fatalf("err = %v, want a *DerivedKeyError for %q matching only ErrDerivedKeyUnavailable", err, op)
	}
	return de
}

var testRequest = keyRequest{rootKey: rootKeyVCEK, fields: sealFields, vmpl: 1, guestSVN: 3, tcbVersion: 0x0807000000000304}

func TestKeyRequest_EncodesMsgKeyReqAndDecodesIt(t *testing.T) {
	b := testRequest.encode()
	want := []byte{
		0, 0, 0, 0, // ROOT_KEY_SELECT: VCEK
		0, 0, 0, 0, // reserved
		0x29, 0, 0, 0, 0, 0, 0, 0, // GUEST_FIELD_SELECT: policy, measurement, TCB version
		1, 0, 0, 0, // VMPL
		3, 0, 0, 0, // GUEST_SVN
		0x04, 0x03, 0, 0, 0, 0, 0x07, 0x08, // TCB_VERSION
	}
	if !bytes.Equal(b[:], want) {
		t.Fatalf("encode = %x, want %x", b, want)
	}
	if got, ok := decodeKeyRequest(b[:]); !ok || got != testRequest {
		t.Fatalf("decode = %+v, %v", got, ok)
	}
	b[5] = 1
	if _, ok := decodeKeyRequest(b[:]); ok {
		t.Fatal("decode accepted a reserved byte that is not zero")
	}
	if _, ok := decodeKeyRequest(want[:31]); ok {
		t.Fatal("decode accepted 31 bytes")
	}
}

func TestTCBAtMost_ComparesEachComponent(t *testing.T) {
	for _, c := range []struct {
		a, b uint64
		want bool
	}{
		{0x0807000000000304, 0x0807000000000304, true},
		{0x0707000000000304, 0x0807000000000304, true},
		{0x0807000000000305, 0x0807000000000304, false},
		// A higher component under a lower one is still above it.
		{0x0007000000000400, 0x0807000000000304, false},
	} {
		if got := tcbAtMost(c.a, c.b); got != c.want {
			t.Fatalf("tcbAtMost(%#x, %#x) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestRequestFromReport_RecordsVMPLGuestSVNAndCommittedTCB(t *testing.T) {
	report := make([]byte, snpReportSize)
	binary.LittleEndian.PutUint32(report[offGuestSVN:], 3)
	binary.LittleEndian.PutUint32(report[offVMPL:], 1)
	binary.LittleEndian.PutUint64(report[offCommittedTCB:], 0x0807000000000304)
	req, err := requestFromReport(report)
	if err != nil || req != testRequest {
		t.Fatalf("requestFromReport = %+v, %v, want %+v", req, err, testRequest)
	}
	_, err = requestFromReport(report[:snpReportSize-1])
	wantDerived(t, err, "report")
}

func TestReceiveKey_CopiesTheKeyOrNamesTheRefusal(t *testing.T) {
	dst := make([]byte, derivedKeySize)
	err := receiveKey(dst, func(resp *[keyResponseSize]byte) error {
		for i := keyResponseKeyOffset; i < keyResponseSize; i++ {
			resp[i] = byte(i)
		}
		return nil
	})
	if err != nil || dst[0] != keyResponseKeyOffset || dst[derivedKeySize-1] != keyResponseSize-1 {
		t.Fatalf("receiveKey = %x, %v", dst, err)
	}
	clear(dst)
	err = receiveKey(dst, func(resp *[keyResponseSize]byte) error {
		resp[0] = 0x16
		resp[keyResponseKeyOffset] = 0xff
		return nil
	})
	de := wantDerived(t, err, "derived-key")
	var fe *FirmwareError
	if !errors.As(de, &fe) || fe.Status != 0x16 || fe.Errno != nil {
		t.Fatalf("Cause = %v, want a *FirmwareError with status 0x16", de.Cause)
	}
	if !bytes.Equal(dst, make([]byte, derivedKeySize)) {
		t.Fatalf("a refused response wrote %x", dst)
	}
	inner := errors.New("fill failed")
	if err := receiveKey(dst, func(*[keyResponseSize]byte) error { return inner }); err != inner {
		t.Fatalf("receiveKey = %v, want fill's error", err)
	}
	err = receiveKey(make([]byte, 16), func(*[keyResponseSize]byte) error { return nil })
	wantDerived(t, err, "memory")
}

func TestFirmwareError_SplitsExitInfo2(t *testing.T) {
	errno := &os.SyscallError{Syscall: "ioctl", Err: fs.ErrPermission}
	fe := firmwareError(0x00000002_ffffffff, errno)
	if fe.FWError != 0xffffffff || fe.VMMError != 2 || !errors.Is(fe, fs.ErrPermission) {
		t.Fatalf("firmwareError = %+v", fe)
	}
	if got := fe.Error(); got != "guest request refused: firmware error 0xffffffff, hypervisor error 0x2: ioctl: permission denied" {
		t.Fatalf("Error() = %q", got)
	}
	if got := (&FirmwareError{Status: 0x16}).Error(); got != "firmware refused the key request: status 0x16" {
		t.Fatalf("Error() = %q", got)
	}
}

// testKey is a 32-byte AES key that stands for a derived key in the blob
// codec tests; no derivation is simulated.
func testKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, derivedKeySize)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestBlob_RoundTripsAndRefusesEveryAlteredByte(t *testing.T) {
	dk, key := testKey(t), testKey(t)
	blob, err := sealBlob(dk, testRequest, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(blob) != blobHeaderSize+len(key)+gcmTagSize || blob[0] != blobVersion {
		t.Fatalf("blob of %d bytes, version %d", len(blob), blob[0])
	}
	if enc := testRequest.encode(); !bytes.Equal(blob[1:1+keyRequestSize], enc[:]) {
		t.Fatal("the blob header is not the key request")
	}
	if bytes.Contains(blob, key) {
		t.Fatal("the blob holds the key in the clear")
	}
	got := make([]byte, len(key))
	if err := openBlob(dk, blob, got); err != nil || !bytes.Equal(got, key) {
		t.Fatalf("openBlob = %v", err)
	}
	for i := range blob {
		bad := bytes.Clone(blob)
		bad[i] ^= 0x01
		dst := bytes.Repeat([]byte{0x5a}, len(key))
		if err := openBlob(dk, bad, dst); !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Fatalf("byte %d altered: openBlob = %v, want ErrSealedAuthentication", i, err)
		}
		if !bytes.Equal(dst, bytes.Repeat([]byte{0x5a}, len(key))) {
			t.Fatalf("byte %d altered: the destination was written", i)
		}
	}
	if err := openBlob(testKey(t), blob, got); !errors.Is(err, enclave.ErrSealedAuthentication) {
		t.Fatalf("another derived key: openBlob = %v, want ErrSealedAuthentication", err)
	}
	again, _ := sealBlob(dk, testRequest, key)
	if bytes.Equal(again[blobHeaderSize-gcmNonceSize:blobHeaderSize], blob[blobHeaderSize-gcmNonceSize:blobHeaderSize]) {
		t.Fatal("two seals share a nonce")
	}
}

func TestBlobRequest_RefusesABlobThisGuestDidNotMake(t *testing.T) {
	kp := &KeyProtector{req: testRequest}
	blob, err := sealBlob(testKey(t), testRequest, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if req, err := kp.blobRequest(blob, 32); err != nil || req != testRequest {
		t.Fatalf("blobRequest = %+v, %v", req, err)
	}
	older := testRequest
	older.tcbVersion, older.guestSVN = 0x0807000000000204, 2
	if old, _ := sealBlob(testKey(t), older, make([]byte, 32)); old != nil {
		if req, err := kp.blobRequest(old, 32); err != nil || req != older {
			t.Fatalf("a blob from an older TCB: blobRequest = %+v, %v", req, err)
		}
	}
	refuse := map[string]func() ([]byte, int){
		"short":       func() ([]byte, int) { return blob[:len(blob)-1], 32 },
		"length":      func() ([]byte, int) { return blob, 31 },
		"empty key":   func() ([]byte, int) { return blob[:blobHeaderSize+gcmTagSize], 0 },
		"version":     func() ([]byte, int) { b := bytes.Clone(blob); b[0] = 2; return b, 32 },
		"reserved":    func() ([]byte, int) { b := bytes.Clone(blob); b[5] = 1; return b, 32 },
		"root key":    func() ([]byte, int) { b := bytes.Clone(blob); b[1] = 1; return b, 32 },
		"fields":      func() ([]byte, int) { b := bytes.Clone(blob); b[9] = 0x21; return b, 32 },
		"vmpl":        func() ([]byte, int) { b := bytes.Clone(blob); b[17] = 0; return b, 32 },
		"guest svn":   func() ([]byte, int) { b := bytes.Clone(blob); b[21] = 4; return b, 32 },
		"tcb version": func() ([]byte, int) { b := bytes.Clone(blob); b[25] = 5; return b, 32 },
	}
	for name, mk := range refuse {
		b, n := mk()
		if _, err := kp.blobRequest(b, n); !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Fatalf("%s: blobRequest = %v, want ErrSealedAuthentication", name, err)
		}
	}
}

func TestNewKeyProtector_RefusesWithoutTheGuestDevice(t *testing.T) {
	useDevice(t, filepath.Join(t.TempDir(), "sev-guest"))
	kp, err := NewKeyProtector()
	if kp != nil {
		t.Fatalf("NewKeyProtector returned %v with %v", kp, err)
	}
	if !supported {
		wantDerived(t, err, "")
		return
	}
	if de := wantDerived(t, err, "open"); !errors.Is(de, fs.ErrNotExist) {
		t.Fatalf("Cause = %v, want fs.ErrNotExist", de.Cause)
	}
}

func TestKeyProtector_ChecksContextAndItsMakingBeforeAnyRequest(t *testing.T) {
	useDevice(t, filepath.Join(t.TempDir(), "sev-guest"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	kp := &KeyProtector{req: testRequest}
	if _, err := kp.Protect(ctx, make([]byte, 32)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Protect(canceled) = %v", err)
	}
	if err := kp.Unprotect(ctx, nil, make([]byte, 32)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Unprotect(canceled) = %v", err)
	}
	for _, bad := range []*KeyProtector{nil, {}} {
		_, err := bad.Protect(context.Background(), make([]byte, 32))
		wantDerived(t, err, "derived-key")
		wantDerived(t, bad.Unprotect(context.Background(), nil, make([]byte, 32)), "derived-key")
	}
	if _, err := kp.Protect(context.Background(), nil); !errors.Is(err, enclave.ErrInvalidSize) {
		t.Fatalf("Protect(empty) = %v, want ErrInvalidSize", err)
	}
	// A malformed blob is refused before the device is touched.
	if err := kp.Unprotect(context.Background(), []byte{1}, make([]byte, 32)); !errors.Is(err, enclave.ErrSealedAuthentication) {
		t.Fatalf("Unprotect(1 byte) = %v, want ErrSealedAuthentication", err)
	}
	//nolint:staticcheck // a nil ctx is the background context
	_, err := kp.Protect(nil, make([]byte, 32))
	if supported {
		wantDerived(t, err, "open")
	} else {
		wantDerived(t, err, "")
	}
	blob, _ := sealBlob(testKey(t), testRequest, make([]byte, 32))
	err = kp.Unprotect(context.Background(), blob, make([]byte, 32))
	if supported {
		wantDerived(t, err, "open")
	}
}

func TestKeyProtector_IsAKeyProtectorAndNoBackend(t *testing.T) {
	var v any = &KeyProtector{}
	if _, ok := v.(enclave.KeyProtector); !ok {
		t.Fatal("*KeyProtector is not an enclave.KeyProtector")
	}
	if _, ok := v.(enclave.Backend); ok {
		t.Fatal("*KeyProtector is an enclave.Backend; a confidential VM is not a backend")
	}
}

func TestDerivedKeyError_MatchesUnavailableAndUnwrapsItsCause(t *testing.T) {
	err := error(&DerivedKeyError{Op: "open", Cause: &fs.PathError{Op: "open", Path: "/dev/sev-guest", Err: fs.ErrNotExist}})
	if !errors.Is(err, ErrDerivedKeyUnavailable) || !errors.Is(err, fs.ErrNotExist) || errors.Is(err, ErrTSMReportUnavailable) {
		t.Fatalf("%v matches wrongly", err)
	}
	if got, want := err.Error(), "confidentialvm: SNP derived key open: open /dev/sev-guest: file does not exist"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if bare := (&DerivedKeyError{}); bare.Error() != "confidentialvm: SNP derived key" || bare.Unwrap() != nil {
		t.Fatalf("bare = %q", bare.Error())
	}
}

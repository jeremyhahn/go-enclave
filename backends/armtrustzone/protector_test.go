package armtrustzone

import (
	"bytes"
	"context"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

func TestKeyProtectorInterfaces(t *testing.T) {
	var p any = (&Backend{}).KeyProtector()
	if _, ok := p.(enclave.KeyProtector); !ok {
		t.Error("*KeyProtector is not an enclave.KeyProtector")
	}
	if _, ok := p.(enclave.HealthReporter); !ok {
		t.Error("*KeyProtector is not an enclave.HealthReporter")
	}
	if err := (&Backend{}).KeyProtector().Health(); err != nil {
		t.Errorf("Health() = %v; want nil", err)
	}
}

// The Backend below has no client: a call that reached the device would
// panic, so a returned error proves the refusal came first.

func TestKeyProtectorRefusesEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p := (&Backend{}).KeyProtector()

	blob, err := p.Protect(ctx, []byte("0123456789abcdef0123456789abcdef"))
	if blob != nil || !errors.Is(err, context.Canceled) {
		t.Errorf("Protect(ended) = %v, %v; want nil, context.Canceled", blob, err)
	}

	key := make([]byte, 32)
	if err := p.Unprotect(ctx, []byte("blob"), key); !errors.Is(err, context.Canceled) {
		t.Errorf("Unprotect(ended) = %v; want context.Canceled", err)
	}
	if !bytes.Equal(key, make([]byte, 32)) {
		t.Error("Unprotect(ended) wrote into key")
	}
}

func TestUnprotectRefusesBeforeDevice(t *testing.T) {
	p := (&Backend{}).KeyProtector()
	for _, tc := range []struct {
		name      string
		blob, key []byte
	}{
		{"empty blob", nil, []byte{1, 2, 3}},
		{"oversized blob", make([]byte, sealMaxBlob+1), []byte{1, 2, 3}},
		{"empty key", []byte("blob"), []byte{}},
	} {
		err := p.Unprotect(context.Background(), tc.blob, tc.key)
		if !errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Errorf("%s: Unprotect = %v; want ErrSealedAuthentication", tc.name, err)
		}
		if !bytes.Equal(tc.key, make([]byte, len(tc.key))) {
			t.Errorf("%s: key = %x; want zeroed", tc.name, tc.key)
		}
	}
}

func TestSealNext(t *testing.T) {
	short := &CommandError{Command: taCmdSeal, Code: teecErrorShortBuffer}
	other := &CommandError{Command: taCmdSeal, Code: 0xffff0006}
	for _, tc := range []struct {
		name     string
		err      error
		size     int
		got      uint64
		retried  bool
		wantNext int
		wantErr  error
	}{
		{"done", nil, 96, 60, false, 0, nil},
		{"done, full buffer", nil, 96, 96, false, 0, nil},
		{"empty blob", nil, 96, 0, false, 0, ErrCommandFailed},
		{"overlong blob", nil, 96, 97, false, 0, ErrCommandFailed},
		{"short buffer retried", short, 96, 200, false, 200, nil},
		{"short buffer at the cap", short, 96, sealMaxBlob, false, sealMaxBlob, nil},
		{"short buffer above the cap", short, 96, sealMaxBlob + 1, false, 0, ErrCommandFailed},
		{"short buffer twice", short, 200, 300, true, 0, ErrCommandFailed},
		{"short buffer, no larger size", short, 96, 96, false, 0, ErrCommandFailed},
		{"other command error", other, 96, 0, false, 0, ErrCommandFailed},
		{"context", context.Canceled, 96, 96, false, 0, context.Canceled},
	} {
		next, err := sealNext(tc.err, tc.size, tc.got, tc.retried)
		if next != tc.wantNext || !errors.Is(err, tc.wantErr) || (tc.wantErr == nil) != (err == nil) {
			t.Errorf("%s: sealNext = %d, %v; want %d, %v", tc.name, next, err, tc.wantNext, tc.wantErr)
		}
		if errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Errorf("%s: a SEAL failure matches ErrSealedAuthentication", tc.name)
		}
	}
}

func TestUnsealResult(t *testing.T) {
	devErr := &DeviceError{Endpoint: "/dev/tee0", Op: "invoke", Cause: errors.New("boom")}
	for _, tc := range []struct {
		name    string
		err     error
		got     uint64
		want    int
		wantErr error
	}{
		{"success", nil, 32, 32, nil},
		{"shorter plaintext", nil, 31, 32, enclave.ErrSealedAuthentication},
		{"longer plaintext", nil, 33, 32, enclave.ErrSealedAuthentication},
		{"mac invalid", &CommandError{Command: taCmdUnseal, Code: teecErrorMACInvalid}, 32, 32, enclave.ErrSealedAuthentication},
		{"short buffer", &CommandError{Command: taCmdUnseal, Code: teecErrorShortBuffer}, 64, 32, enclave.ErrSealedAuthentication},
		{"other command error", &CommandError{Command: taCmdUnseal, Code: 0xffff0006}, 32, 32, ErrCommandFailed},
		{"device error", devErr, 32, 32, devErr},
		{"backend closed", ErrBackendClosed, 0, 32, ErrBackendClosed},
		{"context", context.DeadlineExceeded, 32, 32, context.DeadlineExceeded},
	} {
		err := unsealResult(tc.err, tc.got, tc.want)
		if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil) != (err == nil) {
			t.Errorf("%s: unsealResult = %v; want %v", tc.name, err, tc.wantErr)
		}
		if tc.wantErr != enclave.ErrSealedAuthentication && errors.Is(err, enclave.ErrSealedAuthentication) {
			t.Errorf("%s: an infrastructure failure matches ErrSealedAuthentication", tc.name)
		}
	}
}

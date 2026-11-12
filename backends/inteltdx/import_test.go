package inteltdx

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// The tests build the backend directly: New refuses off a TD, and the handle
// layer is plain Go over enclave.NewMemory, which needs no device.

func zeroed(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

func seq(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func importOK(t *testing.T, b *Backend, material []byte, opts ...enclave.ImportOption) *Handle {
	t.Helper()
	h, err := b.Import(context.Background(), material, opts...)
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	th, ok := h.(*Handle)
	if !ok {
		t.Fatalf("Import returned %T, want *Handle", h)
	}
	t.Cleanup(func() { _ = th.Destroy() })
	return th
}

func TestBackendIsImporterNotSweeper(t *testing.T) {
	var b enclave.Backend = &Backend{}
	if _, ok := b.(enclave.Importer); !ok {
		t.Fatal("the backend is not an enclave.Importer")
	}
	// Q7 (recommended: no Sweeper): handles are memory enclaves, which
	// WipeAll already sweeps.
	if _, ok := b.(enclave.Sweeper); ok {
		t.Fatal("the backend is an enclave.Sweeper; Q7 says it is not")
	}
}

func TestImportMaterial(t *testing.T) {
	b := &Backend{}
	want := seq(48)
	material := bytes.Clone(want)
	h := importOK(t, b, material, enclave.WithPurpose(enclave.PurposeMaterial))
	if !zeroed(material) {
		t.Fatal("material not wiped after a successful Import")
	}
	if h.Size() != len(want) || !h.IsAlive() {
		t.Fatalf("Size %d alive %v, want %d true", h.Size(), h.IsAlive(), len(want))
	}
	if h.Backend() != b {
		t.Fatal("Backend() is not the importing backend")
	}
	eq, err := h.EqualTo(want)
	if err != nil || !eq {
		t.Fatalf("EqualTo = %v, %v; want true, nil", eq, err)
	}
	if err := h.WithBytes(func(v []byte) error {
		if !bytes.Equal(v, want) {
			return errors.New("view differs from the imported material")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var ba enclave.ByteAccess
	if !enclave.As(h, &ba) {
		t.Fatal("handle does not reach ByteAccess through enclave.As")
	}
}

func TestImportAES256GCMKey(t *testing.T) {
	for _, p := range []enclave.Purpose{enclave.PurposeWrappingKey, enclave.PurposeDataKey} {
		t.Run(string(p), func(t *testing.T) {
			material := seq(32)
			h := importOK(t, &Backend{}, material,
				enclave.WithPurpose(p), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM))
			if !zeroed(material) {
				t.Fatal("key not wiped after a successful Import")
			}
			if h.Size() != 32 {
				t.Fatalf("Size %d, want 32", h.Size())
			}
		})
	}
}

func TestImportRefusals(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	key := []enclave.ImportOption{
		enclave.WithPurpose(enclave.PurposeDataKey), enclave.WithAlgorithm(enclave.AlgorithmAES256GCM),
	}
	tests := []struct {
		name  string
		ctx   context.Context
		n     int
		opts  []enclave.ImportOption
		check func(error) bool
	}{
		{"wrong algorithm", context.Background(), 32,
			[]enclave.ImportOption{enclave.WithPurpose(enclave.PurposeDataKey), enclave.WithAlgorithm("chacha20-poly1305")},
			func(err error) bool {
				var ce *enclave.CapabilityError
				return errors.As(err, &ce) && ce.Capability == enclave.CapabilityImport && ce.Backend == Name
			}},
		{"31-byte key", context.Background(), 31, key,
			func(err error) bool { return errors.Is(err, enclave.ErrInvalidImport) }},
		{"no purpose", context.Background(), 32, nil,
			func(err error) bool { return errors.Is(err, enclave.ErrInvalidImport) }},
		{"canceled ctx", canceled, 32, key,
			func(err error) bool { return errors.Is(err, context.Canceled) }},
		{"empty material", context.Background(), 0,
			[]enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)},
			func(err error) bool { return err != nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			material := seq(tt.n)
			h, err := (&Backend{}).Import(tt.ctx, material, tt.opts...)
			if h != nil {
				_ = h.Destroy()
				t.Fatalf("Import returned a handle (%T) with err %v", h, err)
			}
			if !tt.check(err) {
				t.Fatalf("Import err = %v (%T)", err, err)
			}
			if !zeroed(material) {
				t.Fatal("material not wiped on a refusal")
			}
		})
	}
}

func TestHandleFreezeAndDestroy(t *testing.T) {
	h := importOK(t, &Backend{}, seq(32), enclave.WithPurpose(enclave.PurposeMaterial))
	var f enclave.Freezer
	if !enclave.As(h, &f) {
		t.Fatal("handle does not reach Freezer through enclave.As")
	}
	if err := h.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	if eq, err := h.EqualTo(seq(32)); err != nil || !eq {
		t.Fatalf("EqualTo after Freeze = %v, %v", eq, err)
	}
	if err := h.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if h.IsAlive() || h.Size() != 0 {
		t.Fatal("handle alive after Destroy")
	}
	if err := h.Destroy(); err != nil {
		t.Fatalf("second Destroy: %v", err)
	}
	if err := h.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("WithBytes after Destroy = %v, want ErrEnclaveDestroyed", err)
	}
	if _, err := h.EqualTo(nil); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("EqualTo after Destroy = %v, want ErrEnclaveDestroyed", err)
	}
	if err := h.Freeze(); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Fatalf("Freeze after Destroy = %v, want ErrEnclaveDestroyed", err)
	}
	if h.Backend() == nil {
		t.Fatal("Backend() nil after Destroy")
	}
}

// frozenWriteEnv makes the test binary, re-run as a child, write through a
// frozen handle's view; the write must fault, so the child must not exit 0.
const frozenWriteEnv = "INTELTDX_TEST_FROZEN_WRITE"

func TestHandleFreezeIsReadOnly(t *testing.T) {
	if os.Getenv(frozenWriteEnv) == "1" {
		h, err := (&Backend{}).Import(context.Background(), seq(32), enclave.WithPurpose(enclave.PurposeMaterial))
		if err != nil {
			os.Exit(3)
		}
		if err := h.(*Handle).Freeze(); err != nil {
			os.Exit(4)
		}
		_ = h.(*Handle).WithBytes(func(v []byte) error { v[0] ^= 0xff; return nil })
		os.Exit(0) // reached only if the write did not fault
	}
	if runtime.GOOS != "linux" {
		t.Skip("the fault is checked where the memory enclave is mprotect'd: Linux, the runtime target")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestHandleFreezeIsReadOnly$")
	cmd.Env = append(os.Environ(), frozenWriteEnv+"=1")
	err := cmd.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("child: %v, want a fault on the frozen write", err)
	}
	if code := ee.ExitCode(); code == 3 || code == 4 {
		t.Fatalf("child could not set up the frozen handle (exit %d)", code)
	}
}

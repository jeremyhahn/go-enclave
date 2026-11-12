package nvblackwell

import (
	"bytes"
	"context"
	"errors"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
)

// testInner stands in for the CPU TEE backend New composes: a Go test double
// over enclave.NewMemory that claims Importer, Attester, Prober and a
// confining Confiner. It fakes no device: no file under /dev, /proc or /sys.
// When noFreeze is set its handles lack Freezer.
type testInner struct {
	noFreeze bool
	last     enclave.Handle
}

func (*testInner) Name() string                { return "test-cvm" }
func (*testInner) Rank() int                   { return 5 }
func (*testInner) Probe(context.Context) error { return nil }
func (*testInner) ConfinesProcess() bool       { return true }
func (*testInner) Attest(context.Context, []byte) (enclave.Evidence, error) {
	return enclave.Evidence{}, errors.New("test inner does not attest")
}

func (in *testInner) Import(ctx context.Context, material []byte, opts ...enclave.ImportOption) (enclave.Handle, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			clear(material)
			return nil, err
		}
	}
	if _, err := enclave.NewImportSpec(opts...); err != nil {
		clear(material)
		return nil, err
	}
	m, err := enclave.NewMemory(material)
	if err != nil {
		return nil, err
	}
	if in.noFreeze {
		h := &plainHandle{ByteAccess: m, b: in}
		in.last = h
		return h, nil
	}
	h := &innerHandle{plainHandle{ByteAccess: m, b: in}}
	in.last = h
	return h, nil
}

// plainHandle is a test inner's handle without Freezer.
type plainHandle struct {
	enclave.ByteAccess
	b enclave.Backend
}

func (h *plainHandle) Backend() enclave.Backend { return h.b }

// innerHandle is a test inner's handle with Freezer.
type innerHandle struct{ plainHandle }

func (h *innerHandle) Freeze() error {
	f, ok := h.ByteAccess.(enclave.Freezer)
	if !ok {
		return errors.New("memory handle is no Freezer")
	}
	return f.Freeze()
}

var (
	_ enclave.Importer = (*testInner)(nil)
	_ enclave.Attester = (*testInner)(nil)
	_ enclave.Prober   = (*testInner)(nil)
	_ enclave.Confiner = (*testInner)(nil)
)

// testBackend builds the backend around in, bypassing New's host probe.
func testBackend(in *testInner) *Backend {
	return &Backend{inner: in, rank: in.Rank() + 1}
}

func TestImportWrapsInnersHandle(t *testing.T) {
	in := &testInner{}
	b := testBackend(in)
	material := []byte("sixteen byte key")
	h, err := b.Import(context.Background(), material, enclave.WithPurpose(enclave.PurposeMaterial))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !bytes.Equal(material, make([]byte, len(material))) {
		t.Errorf("Import left the caller's slice unwiped")
	}
	if h.Backend() != enclave.Backend(b) {
		t.Errorf("Backend() = %v, want the nvidia-blackwell backend", h.Backend())
	}
	if h.Size() != 16 || !h.IsAlive() {
		t.Errorf("Size, IsAlive = %d, %v, want 16, true", h.Size(), h.IsAlive())
	}
	ba, ok := h.(enclave.ByteAccess)
	if !ok {
		t.Fatalf("handle %T is no ByteAccess", h)
	}
	if err := ba.WithBytes(func(p []byte) error {
		if string(p) != "sixteen byte key" {
			t.Errorf("WithBytes view = %q", p)
		}
		return nil
	}); err != nil {
		t.Fatalf("WithBytes: %v", err)
	}
	if eq, err := ba.EqualTo([]byte("sixteen byte key")); err != nil || !eq {
		t.Errorf("EqualTo = %v, %v, want true, nil", eq, err)
	}
	f, ok := h.(enclave.Freezer)
	if !ok {
		t.Fatalf("handle %T is no Freezer", h)
	}
	if err := f.Freeze(); err != nil {
		t.Fatalf("Freeze: %v", err)
	}
	var ih *innerHandle
	if !enclave.As(h, &ih) || ih != in.last {
		t.Fatalf("enclave.As did not reach inner's handle")
	}
	if err := h.Destroy(); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if h.IsAlive() || ih.IsAlive() {
		t.Errorf("after Destroy: wrapper alive %v, inner's handle alive %v", h.IsAlive(), ih.IsAlive())
	}
	if !errors.Is(ba.WithBytes(func([]byte) error { return nil }), enclave.ErrEnclaveDestroyed) {
		t.Errorf("WithBytes after Destroy is not ErrEnclaveDestroyed")
	}
	if h.Backend() != enclave.Backend(b) {
		t.Errorf("Backend() after Destroy changed")
	}
}

func TestImportRefusesAHandleWithoutFreezer(t *testing.T) {
	in := &testInner{noFreeze: true}
	b := testBackend(in)
	h, err := b.Import(context.Background(), []byte("material"), enclave.WithPurpose(enclave.PurposeMaterial))
	if h != nil {
		t.Fatalf("Import = %v, want nil", h)
	}
	var ce *enclave.CapabilityError
	if !errors.As(err, &ce) || !errors.Is(err, enclave.ErrCapabilityUnsupported) {
		t.Fatalf("Import error = %v, want a *enclave.CapabilityError", err)
	}
	if ce.Backend != in.Name() || ce.Capability != enclave.CapabilityFreeze {
		t.Errorf("CapabilityError = %+v, want backend %q lacking %q", ce, in.Name(), enclave.CapabilityFreeze)
	}
	if in.last == nil || in.last.IsAlive() {
		t.Errorf("inner's handle was not destroyed")
	}
}

func TestImportPassesInnersErrorsThrough(t *testing.T) {
	in := &testInner{}
	b := testBackend(in)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	material := []byte("material")
	if _, err := b.Import(ctx, material, enclave.WithPurpose(enclave.PurposeMaterial)); !errors.Is(err, context.Canceled) {
		t.Errorf("Import(cancelled ctx) error = %v, want context.Canceled", err)
	}
	if !bytes.Equal(material, make([]byte, len(material))) {
		t.Errorf("Import(cancelled ctx) left the caller's slice unwiped")
	}
	if _, err := b.Import(context.Background(), []byte("material")); !errors.Is(err, enclave.ErrInvalidImport) {
		t.Errorf("Import(no purpose) error = %v, want ErrInvalidImport", err)
	}
	if _, err := b.Import(context.Background(), []byte("material"), nil); !errors.Is(err, enclave.ErrInvalidImport) {
		t.Errorf("Import(nil option) error = %v, want ErrInvalidImport", err)
	}
	if in.last != nil {
		t.Errorf("inner made a handle on a refused import")
	}
}

func TestBackendIsAnImporterAndNoSweeper(t *testing.T) {
	var b enclave.Backend = testBackend(&testInner{})
	if _, ok := b.(enclave.Importer); !ok {
		t.Errorf("%T is no enclave.Importer", b)
	}
	if _, ok := b.(enclave.Sweeper); ok {
		t.Errorf("%T is an enclave.Sweeper; inner sweeps its own handles", b)
	}
}

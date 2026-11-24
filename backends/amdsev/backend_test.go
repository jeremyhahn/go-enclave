package amdsev

import (
	"context"
	"errors"
	"syscall"
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

func newAllocator(t *testing.T) enclave.Allocator {
	t.Helper()
	a, err := enclave.NewAllocator(1 << 20)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestBackendConformance(t *testing.T) {
	a := newAllocator(t)
	cfg := backendtest.Config{
		New:                 func() (enclave.Backend, error) { return newBackend(a, successGuest().os()) },
		BackendCapabilities: []enclave.Capability{enclave.CapabilityImport, enclave.CapabilityConfine},
		Handles: []backendtest.HandleCase{{
			Name:         "material",
			Import:       []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)},
			ImportSize:   32,
			Capabilities: []enclave.Capability{enclave.CapabilityBytes, enclave.CapabilityFreeze},
		}},
		Logf: t.Logf,
	}
	if err := backendtest.TestBackend(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

func TestBackendConfinesProcess(t *testing.T) {
	b, err := newBackend(newAllocator(t), successGuest().os())
	if err != nil {
		t.Fatal(err)
	}
	if b.Name() != Name {
		t.Fatalf("Name() = %q", b.Name())
	}
	c, ok := b.(enclave.Confiner)
	if !ok || !c.ConfinesProcess() {
		t.Fatal("backend does not confine the process")
	}
	if _, ok := b.(enclave.Prober); ok {
		t.Fatal("backend is a Prober")
	}
	h, err := b.(enclave.Importer).Import(context.Background(), []byte("0123456789abcdef0123456789abcdef"),
		enclave.WithPurpose(enclave.PurposeMaterial))
	if err != nil {
		t.Fatal(err)
	}
	if h.Backend() != b {
		t.Fatal("handle reports another backend")
	}
	if err := h.Destroy(); err != nil {
		t.Fatal(err)
	}
}

func TestBackendImportRefused(t *testing.T) {
	b, err := newBackend(newAllocator(t), successGuest().os())
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.(enclave.Importer).Import(context.Background(), nil)
	if err == nil {
		t.Fatal("empty material admitted")
	}
}

func TestNewRefusesWithoutSNP(t *testing.T) {
	for name, f := range map[string]*fakeGuest{
		"host or plain VM":    {openErr: syscall.ENOENT, mkdirErr: syscall.ENOENT},
		"SEV-ES guest":        {openErr: syscall.ENOENT, provider: "none", mkdirErr: syscall.ENOENT},
		"TDX guest":           {openErr: syscall.ENOENT, provider: "tdx_guest"},
		"device refuses user": {openErr: syscall.EACCES, mkdirErr: syscall.EACCES},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := newBackend(newAllocator(t), f.os())
			if b != nil || !errors.Is(err, ErrSNPGuestUnavailable) {
				t.Fatalf("newBackend = %v, %v; want ErrSNPGuestUnavailable", b, err)
			}
		})
	}
}

func TestNewRefusesNilAllocator(t *testing.T) {
	if _, err := New(nil); !errors.Is(err, enclave.ErrAllocatorNotConstructed) {
		t.Fatalf("New(nil) = %v", err)
	}
}

// TestNewOnThisHost runs New against the real kernel. It holds the error
// contract wherever it runs: a backend that confines the process inside an
// SEV-SNP guest, an error matching ErrSNPGuestUnavailable everywhere else.
func TestNewOnThisHost(t *testing.T) {
	b, err := New(newAllocator(t))
	if err != nil {
		if !errors.Is(err, ErrSNPGuestUnavailable) {
			t.Fatalf("New = %v, want ErrSNPGuestUnavailable", err)
		}
		return
	}
	if c, ok := b.(enclave.Confiner); !ok || !c.ConfinesProcess() {
		t.Fatal("backend does not confine the process")
	}
}

// otherImportAllocator is an Allocator whose Import makes a handle that is
// not a locked enclave.
type otherImportAllocator struct {
	enclave.Allocator
	destroyed bool
}

type bareHandle struct{ a *otherImportAllocator }

func (bareHandle) Size() int                { return 0 }
func (bareHandle) IsAlive() bool            { return true }
func (h bareHandle) Destroy() error         { h.a.destroyed = true; return nil }
func (bareHandle) Backend() enclave.Backend { return enclave.DefaultBackend() }
func (a *otherImportAllocator) Import(context.Context, []byte, ...enclave.ImportOption) (enclave.Handle, error) {
	return bareHandle{a: a}, nil
}

func TestBackendImportForeignHandle(t *testing.T) {
	a := &otherImportAllocator{Allocator: newAllocator(t)}
	b, err := newBackend(a, successGuest().os())
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.(enclave.Importer).Import(context.Background(), []byte{1})
	if !errors.Is(err, enclave.ErrCapabilityUnsupported) || !a.destroyed {
		t.Fatalf("Import = %v, destroyed %v", err, a.destroyed)
	}
}

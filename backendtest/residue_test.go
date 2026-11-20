//go:build linux

package backendtest

import (
	"context"
	"crypto/rand"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"

	enclave "github.com/jeremyhahn/go-enclave"
)

// signalingHandle is a compliant locked region whose thread takes a signal
// as soon as the caller's WithBytes callback returns. Signals land at any
// instruction, so a backend cannot prevent this one: the kernel saves the
// thread's registers, vector registers included, into a frame on the
// thread's signal stack, which lives in the Go heap and is never cleared.
type signalingHandle struct{ enclave.ByteAccess }

func (h signalingHandle) WithBytes(fn func([]byte) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return h.ByteAccess.WithBytes(func(b []byte) error {
		err := fn(b)
		_ = unix.Tgkill(unix.Getpid(), unix.Gettid(), unix.SIGURG)
		return err
	})
}

// TestBackendConformance_ResidueHarnessLeavesNoRegisterCopy proves the
// residue check plants no copy of its own: the harness reads the material
// into its needle, and if that read keeps the material whole in registers, a
// signal on the thread writes it into the Go heap, where the sweep after
// Destroy finds it and blames a backend that kept nothing.
func TestBackendConformance_ResidueHarnessLeavesNoRegisterCopy(t *testing.T) {
	cfg := Config{
		New: func() (enclave.Backend, error) { return enclave.DefaultBackend(), nil },
		Handles: []HandleCase{{
			Name: "signaled-region",
			New: func(context.Context, enclave.Backend) (enclave.Handle, error) {
				m, err := enclave.NewMemorySized(32)
				if err != nil {
					return nil, err
				}
				if err := m.WithBytes(func(b []byte) error {
					_, err := rand.Read(b)
					return err
				}); err != nil {
					_ = m.Destroy()
					return nil, err
				}
				return signalingHandle{m}, nil
			},
			Capabilities: []enclave.Capability{enclave.CapabilityBytes},
		}},
	}
	for i := range 20 {
		r := &report{ctx: context.Background(), logf: t.Logf}
		checkResidue(r, cfg)
		if len(r.findings) > 0 {
			t.Fatalf("round %d: the residue check reported a compliant region: %v", i, r.findings)
		}
	}
}

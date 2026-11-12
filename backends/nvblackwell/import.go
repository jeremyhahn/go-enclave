package nvblackwell

import (
	"context"
	"errors"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Import moves material into inner, the CPU TEE backend, and returns its
// handle wrapped so Backend() reports this backend. The GPUs hold no host
// material: the confidential VM's memory does, so inner's import is the
// import. inner resolves opts and checks ctx, and its errors return
// unchanged; inner wipes material on every path.
//
// The wrapped handle is [enclave.ByteAccess] and [enclave.Freezer], and
// [enclave.As] reaches inner's handle through it. A handle inner makes
// without both is destroyed and refused with a [*enclave.CapabilityError]
// naming inner and the missing capability, joined with any error Destroy
// returns.
//
// The backend is no [enclave.Sweeper]: the handles are inner's, swept as
// inner's are.
func (b *Backend) Import(ctx context.Context, material []byte, opts ...enclave.ImportOption) (enclave.Handle, error) {
	h, err := b.inner.Import(ctx, material, opts...)
	if err != nil {
		return nil, err
	}
	refuse := func(c enclave.Capability) error {
		capErr := &enclave.CapabilityError{Backend: b.inner.Name(), Capability: c}
		return errors.Join(capErr, h.Destroy())
	}
	ba, ok := h.(enclave.ByteAccess)
	if !ok {
		return nil, refuse(enclave.CapabilityBytes)
	}
	f, ok := h.(enclave.Freezer)
	if !ok {
		return nil, refuse(enclave.CapabilityFreeze)
	}
	return &handle{ByteAccess: ba, freezer: f, b: b}, nil
}

// handle is inner's handle as this backend returns it: every method is
// inner's but Backend, which reports this backend.
type handle struct {
	enclave.ByteAccess
	freezer enclave.Freezer
	b       *Backend
}

// Backend returns the nvidia-blackwell backend that made the handle.
func (h *handle) Backend() enclave.Backend { return h.b }

// Freeze makes inner's material read-only.
func (h *handle) Freeze() error { return h.freezer.Freeze() }

// As reaches inner's handle, the wrapper contract of [enclave.As].
func (h *handle) As(target any) bool { return enclave.As(h.ByteAccess, target) }

var (
	_ enclave.Importer   = (*Backend)(nil)
	_ enclave.ByteAccess = (*handle)(nil)
	_ enclave.Freezer    = (*handle)(nil)
)

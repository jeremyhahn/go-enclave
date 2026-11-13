package inteltdx

import (
	"context"

	enclave "github.com/jeremyhahn/go-enclave"
)

// aes256KeyBytes is the key length enclave.AlgorithmAES256GCM takes.
const aes256KeyBytes = 32

// Import satisfies enclave.Importer. The material goes into a memory enclave
// from enclave.NewMemory inside the TD (design Q6, recommended option): every
// memory-enclave guarantee holds there, and the TD's private memory keeps the
// host out. A memory enclave has ByteAccess, which meets every purpose's
// contract, so Import takes PurposeMaterial and the key purposes for
// AES-256-GCM. A key for any other algorithm is a *enclave.CapabilityError
// naming enclave.CapabilityImport, and a key length AES-256-GCM does not take
// is enclave.ErrInvalidImport, both before any memory is mapped. The caller's
// slice is wiped on every return path.
//
// The backend keeps no registry of its handles and is not an enclave.Sweeper
// (design Q7, recommended option): the handles are memory enclaves, which
// enclave.WipeAll's first phase already sweeps.
func (b *Backend) Import(ctx context.Context, material []byte, opts ...enclave.ImportOption) (enclave.Handle, error) {
	defer enclave.Wipe(material)
	if err := b.unconstructed(); err != nil {
		return nil, err
	}
	spec, err := enclave.NewImportSpec(opts...)
	if err != nil {
		return nil, err
	}
	if spec.Purpose != enclave.PurposeMaterial {
		if spec.Algorithm != enclave.AlgorithmAES256GCM {
			return nil, &enclave.CapabilityError{Backend: Name, Capability: enclave.CapabilityImport}
		}
		if len(material) != aes256KeyBytes {
			return nil, enclave.ErrInvalidImport
		}
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	m, err := enclave.NewMemory(material)
	if err != nil {
		// Never a typed nil inside the Handle.
		return nil, err
	}
	var f enclave.Freezer
	if !enclave.As(m, &f) {
		// Every memory enclave is a Freezer; release it rather than hand
		// out a handle that breaks its contract.
		_ = m.Destroy()
		return nil, &enclave.CapabilityError{Backend: Name, Capability: enclave.CapabilityImport}
	}
	return &Handle{m: m, f: f, b: b}, nil
}

// Handle is an intel-tdx handle: a memory enclave inside the TD, reporting
// the backend instance that made it. It implements enclave.ByteAccess and
// enclave.Freezer. Its methods dereference h: a nil *Handle is outside the
// contract.
type Handle struct {
	m enclave.ByteAccess
	f enclave.Freezer
	b *Backend
}

// Size reports the length of the material, or 0 once it is destroyed.
func (h *Handle) Size() int { return h.m.Size() }

// IsAlive reports whether the handle still holds its material.
func (h *Handle) IsAlive() bool { return h.m.IsAlive() }

// Destroy wipes and releases the material; it is idempotent.
func (h *Handle) Destroy() error { return h.m.Destroy() }

// Backend returns the backend that made the handle, also once destroyed.
func (h *Handle) Backend() enclave.Backend { return h.b }

// WithBytes calls fn with a view of the material, valid only during fn.
func (h *Handle) WithBytes(fn func([]byte) error) error { return h.m.WithBytes(fn) }

// EqualTo reports, in constant time, whether the handle holds exactly other.
func (h *Handle) EqualTo(other []byte) (bool, error) { return h.m.EqualTo(other) }

// Freeze makes the material read-only.
func (h *Handle) Freeze() error { return h.f.Freeze() }

// As exposes the wrapped memory enclave, so enclave.As reaches its
// capabilities.
func (h *Handle) As(target any) bool { return enclave.As(h.m, target) }

var (
	_ enclave.Importer   = (*Backend)(nil)
	_ enclave.Confiner   = (*Backend)(nil)
	_ enclave.ByteAccess = (*Handle)(nil)
	_ enclave.Freezer    = (*Handle)(nil)
)

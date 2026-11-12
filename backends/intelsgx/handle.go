package intelsgx

import (
	"context"
	"errors"

	"github.com/jeremyhahn/go-enclave"
)

// aes256KeyBytes is the key length [enclave.AlgorithmAES256GCM] takes.
const aes256KeyBytes = 32

// Interface checks: the backend imports and sweeps, and its handles give
// byte access and freeze.
var (
	_ enclave.Importer   = (*Backend)(nil)
	_ enclave.Sweeper    = (*Backend)(nil)
	_ enclave.ByteAccess = (*handle)(nil)
	_ enclave.Freezer    = (*handle)(nil)
)

// Import moves material into a new handle, as [enclave.Importer] describes.
//
// The design's Q7 leaves the handle's storage open; this takes the
// recommended option: the material lives in a memory enclave from
// [enclave.NewMemory] inside the SGX enclave, through the exported API only,
// so SGX2 page permissions are not required. The enclave boundary is what
// keeps the material from the host; the memory enclave adds the locked,
// guarded pages it has everywhere.
//
// Import takes [enclave.PurposeMaterial], and [enclave.PurposeWrappingKey]
// and [enclave.PurposeDataKey] for [enclave.AlgorithmAES256GCM] only; any
// other algorithm is a [*enclave.CapabilityError] naming
// [enclave.CapabilityImport]. The caller's slice is wiped on every return
// path.
func (b *Backend) Import(ctx context.Context, material []byte, opts ...enclave.ImportOption) (enclave.Handle, error) {
	defer enclave.Wipe(material)
	spec, err := enclave.NewImportSpec(opts...)
	if err != nil {
		return nil, err
	}
	switch spec.Purpose {
	case enclave.PurposeMaterial:
	default:
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
	if len(material) == 0 {
		return nil, enclave.ErrEmptyEnclave
	}
	mem, err := enclave.NewMemory(material)
	if err != nil {
		// Never a typed nil inside the Handle.
		return nil, err
	}
	h := &handle{mem: mem, backend: b}
	b.track(h)
	return h, nil
}

// Sweep destroys every live handle this backend made and returns how many it
// could not release, as [enclave.Sweeper] describes. The memory enclaves'
// Destroy waits out in-flight borrows itself, so ctx bounds nothing here; a
// nil or done ctx still releases everything.
func (b *Backend) Sweep(_ context.Context) (held int, err error) {
	b.handlesMu.Lock()
	live := make([]*handle, 0, len(b.handles))
	for h := range b.handles {
		live = append(live, h)
	}
	b.handlesMu.Unlock()

	var errs []error
	for _, h := range live {
		if derr := h.Destroy(); derr != nil {
			held++
			errs = append(errs, derr)
		}
	}
	return held, errors.Join(errs...)
}

// track records a live handle for [Backend.Sweep].
func (b *Backend) track(h *handle) {
	b.handlesMu.Lock()
	defer b.handlesMu.Unlock()
	if b.handles == nil {
		b.handles = make(map[*handle]struct{})
	}
	b.handles[h] = struct{}{}
}

// forget drops a destroyed handle from the registry.
func (b *Backend) forget(h *handle) {
	b.handlesMu.Lock()
	defer b.handlesMu.Unlock()
	delete(b.handles, h)
}

// handle is an imported secret: a memory enclave it delegates to, and the
// backend that made it.
type handle struct {
	mem     enclave.ByteAccess
	backend *Backend
}

// Size reports the material's length, or 0 once destroyed.
func (h *handle) Size() int { return h.mem.Size() }

// IsAlive reports whether the handle still holds its material.
func (h *handle) IsAlive() bool { return h.mem.IsAlive() }

// Backend returns the backend that made the handle.
func (h *handle) Backend() enclave.Backend { return h.backend }

// WithBytes calls fn with a view of the material.
func (h *handle) WithBytes(fn func([]byte) error) error { return h.mem.WithBytes(fn) }

// EqualTo reports, in constant time, whether the handle holds exactly other.
func (h *handle) EqualTo(other []byte) (bool, error) { return h.mem.EqualTo(other) }

// Freeze makes the material read-only.
func (h *handle) Freeze() error {
	f, ok := h.mem.(enclave.Freezer)
	if !ok {
		return &enclave.CapabilityError{Backend: Name, Capability: enclave.CapabilityFreeze}
	}
	return f.Freeze()
}

// Destroy wipes the material and drops the handle from the registry. It is
// idempotent; an error leaves the handle registered so Sweep retries it.
func (h *handle) Destroy() error {
	if err := h.mem.Destroy(); err != nil {
		return err
	}
	h.backend.forget(h)
	return nil
}

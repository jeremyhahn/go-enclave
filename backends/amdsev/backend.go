package amdsev

import (
	"context"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Name is the backend's registered name.
const Name = "sev-snp"

// New proves that this process runs inside an SEV-SNP guest and returns a
// backend whose handles are locked-memory enclaves admitted through a. The
// backend is an [enclave.Importer] and an [enclave.Confiner] whose
// ConfinesProcess reports true.
//
// It returns [enclave.ErrAllocatorNotConstructed] for a nil a, and an error
// matching [ErrSNPGuestUnavailable] (a [*GuestError]) on a host, a plain VM,
// or an SEV or SEV-ES guest without SNP.
//
// The backend is not an [enclave.Prober]: its handles are the same locked
// memory the default backend makes, so [enclave.Detect] has no reason to
// prefer it. main registers it with [enclave.Register] and builds the Sealer
// on it.
func New(a enclave.Allocator) (enclave.Backend, error) {
	return newBackend(a, hostOS())
}

// newBackend is New over the seam g.
func newBackend(a enclave.Allocator, g guestOS) (enclave.Backend, error) {
	if a == nil {
		return nil, enclave.ErrAllocatorNotConstructed
	}
	if err := g.detect(devicePath, tsmRoot); err != nil {
		return nil, err
	}
	return &backend{allocator: a}, nil
}

// backend is the SEV-SNP Confiner over an Allocator.
type backend struct {
	allocator enclave.Allocator
}

// Name is [Name].
func (*backend) Name() string { return Name }

// ConfinesProcess reports true: New proved the process runs inside an
// SEV-SNP guest, whose memory the platform encrypts against the host.
func (*backend) ConfinesProcess() bool { return true }

// Import admits material through the allocator, as [enclave.Allocator]'s
// Import does, and returns a handle whose Backend is this backend.
func (b *backend) Import(ctx context.Context, material []byte, opts ...enclave.ImportOption) (enclave.Handle, error) {
	h, err := b.allocator.Import(ctx, material, opts...)
	if err != nil {
		return nil, err
	}
	m, ok := h.(lockedEnclave)
	if !ok {
		_ = h.Destroy()
		return nil, &enclave.CapabilityError{Backend: Name, Capability: enclave.CapabilityBytes}
	}
	return &handle{lockedEnclave: m, backend: b}, nil
}

// lockedEnclave is what an Allocator's handles are.
type lockedEnclave interface {
	enclave.ByteAccess
	enclave.Freezer
}

// handle is a locked-memory enclave reporting the SEV-SNP backend as its
// maker.
type handle struct {
	lockedEnclave
	backend *backend
}

// Backend returns the SEV-SNP backend that made the handle.
func (h *handle) Backend() enclave.Backend { return h.backend }

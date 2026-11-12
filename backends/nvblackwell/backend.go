package nvblackwell

import (
	"context"
	"errors"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Name is the backend's name, as the design gives it.
const Name = "nvidia-blackwell"

// ErrNoInner reports [New] called without the CPU TEE backend to compose.
var ErrNoInner = errors.New("nvblackwell: New needs the CPU TEE backend (intel-tdx or amd-sev) to compose")

// Backend is the nvidia-blackwell backend: the CPU TEE backend main built
// (inner), and the NVIDIA GPUs the CVM sees.
//
// It implements enclave.Backend, enclave.Confiner and enclave.Prober. Import
// (delegating to inner) and Attest (inner's report and each GPU's) are later
// slices, as is the NVML half of [Probe]. It is no enclave.Sweeper: the
// handles will be inner's, swept as inner's are.
type Backend struct {
	inner enclave.Prober
	rank  int
}

var (
	_ enclave.Backend  = (*Backend)(nil)
	_ enclave.Confiner = (*Backend)(nil)
	_ enclave.Prober   = (*Backend)(nil)
)

// New composes the backend over inner, the CPU TEE backend main built (the
// design's Q2, recommended: a constructor argument, so no lookup runs at
// import and either CPU backend works).
//
// It refuses an inner that is not an enclave.Importer, enclave.Attester and
// enclave.Prober, and an enclave.Confiner whose ConfinesProcess is true, with
// an *enclave.CapabilityError naming inner and the first capability missing,
// in that order. It then runs the backend's Probe, as arm-trustzone's
// Connect does, and returns its typed error: on a host without the hardware
// that is a [*DriverError] or [*PlatformError], or inner's own probe error.
// Nothing registers: main calls enclave.Register if it wants detection to
// see the backend.
func New(inner enclave.Backend) (*Backend, error) {
	if inner == nil {
		return nil, ErrNoInner
	}
	refuse := func(c enclave.Capability) error {
		return &enclave.CapabilityError{Backend: inner.Name(), Capability: c}
	}
	if _, ok := inner.(enclave.Importer); !ok {
		return nil, refuse(enclave.CapabilityImport)
	}
	if _, ok := inner.(enclave.Attester); !ok {
		return nil, refuse(enclave.CapabilityAttest)
	}
	p, ok := inner.(enclave.Prober)
	if !ok {
		return nil, refuse(enclave.CapabilityProbe)
	}
	if c, ok := inner.(enclave.Confiner); !ok || !c.ConfinesProcess() {
		return nil, refuse(enclave.CapabilityConfine)
	}
	// Rank is inner's plus one, fixed here (the design's Q3, recommended):
	// above the CVM alone, so Detect prefers the attestation that covers the
	// GPUs when they are ready and falls back to inner by rank when not.
	b := &Backend{inner: p, rank: p.Rank() + 1}
	if err := b.Probe(context.Background()); err != nil {
		return nil, err
	}
	return b, nil
}

// Name returns [Name].
func (*Backend) Name() string { return Name }

// Rank returns inner's rank plus one, fixed at construction.
func (b *Backend) Rank() int { return b.rank }

// ConfinesProcess reports true: [New] admits only an inner that confines the
// process, and the GPUs are inside that boundary.
func (*Backend) ConfinesProcess() bool { return true }

// Probe checks ctx, runs inner's Probe and returns its error unchanged, then
// runs the package's [Probe] for the GPU side. It fetches no evidence. A nil
// ctx never ends.
func (b *Backend) Probe(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if err := b.inner.Probe(ctx); err != nil {
		return err
	}
	return Probe(ctx)
}

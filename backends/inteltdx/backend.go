package inteltdx

import (
	"context"
	"sync"
)

// Name is the name the backend is registered under: the SPEC row's name.
const Name = "intel-tdx"

// rank is docs/backends/intel-tdx.md Q2's recommended value, the one every
// confidential-VM backend reports: above locked memory (0) and secretmem
// (1), with room for further software backends between.
const rank = 10

// Backend is the intel-tdx backend: a process running inside a TDX trust
// domain. Only [New] makes one, and only inside a TD that passes the probe.
// It is not a Sweeper (Q7, recommended): its handles will wrap memory
// enclaves, which WipeAll's first phase sweeps already.
type Backend struct {
	// mu serializes Attest. The field also gives the struct a size, so two
	// backends never share an address: a handle names its maker by identity.
	mu sync.Mutex
}

// New probes the host as [Backend.Probe] does and returns the backend when
// the probe passes. Off a TD it returns [*GuestDeviceError] (ENOENT), in a
// TD launched with DEBUG [ErrDebugTD], and without a quote service
// [*TSMReportError]. Nothing registers at import: main registers what New
// returns.
func New() (*Backend, error) {
	b := &Backend{}
	if err := b.Probe(context.Background()); err != nil {
		return nil, err
	}
	return b, nil
}

// Name is [Name].
func (b *Backend) Name() string { return Name }

// Rank is 10, above the software backends.
func (b *Backend) Rank() int { return rank }

// ConfinesProcess is true: [New] succeeds only inside a TD, so the process
// runs inside the backend's boundary.
func (b *Backend) ConfinesProcess() bool { return true }

// Probe reports whether this process runs in a TD that can attest: it gets
// a TDREPORT through /dev/tdx_guest, refuses a DEBUG TD, and produces one
// quote through configfs-tsm, which it discards (Q3, recommended). ctx
// bounds the wait for the quote; a nil ctx never ends.
func (b *Backend) Probe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return probe(ctx)
}

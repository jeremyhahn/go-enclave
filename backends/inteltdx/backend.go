package inteltdx

import (
	"context"
)

// Name is the name the backend is registered under: the SPEC row's name.
const Name = "intel-tdx"

// rank is docs/backends/intel-tdx.md Q2's recommended value, the one every
// confidential-VM backend reports: above locked memory (0) and secretmem
// (1), with room for further software backends between.
const rank = 10

// opConstruct is the GuestDeviceError Op of a Backend [New] did not make.
const opConstruct = "construct"

// Backend is the intel-tdx backend: a process running inside a TDX trust
// domain. Only [New] makes one, and only inside a TD that passes the probe.
// A Backend built any other way confines nothing and refuses Import and
// Attest with a [*GuestDeviceError].
// It is not a Sweeper (Q7, recommended): its handles will wrap memory
// enclaves, which WipeAll's first phase sweeps already.
type Backend struct {
	// slot is a one-slot semaphore that serializes Attest; a waiter selects
	// on its ctx, so an ended deadline never waits behind a slow quote.
	// Only New makes it.
	slot chan struct{}
	// constructed is set only by New, once the probe passes.
	constructed bool
}

// newBackend makes a Backend as New does, without the probe.
func newBackend() *Backend {
	return &Backend{slot: make(chan struct{}, 1), constructed: true}
}

// unconstructed is the refusal of a Backend New did not make.
func (b *Backend) unconstructed() error {
	if b.constructed {
		return nil
	}
	return &GuestDeviceError{Op: opConstruct}
}

// New probes the host as [Backend.Probe] does and returns the backend when
// the probe passes. Off a TD it returns [*GuestDeviceError] (ENOENT), in a
// TD launched with DEBUG [ErrDebugTD], and without a quote service
// [*TSMReportError]. Nothing registers at import: main registers what New
// returns.
func New() (*Backend, error) {
	b := newBackend()
	if err := b.Probe(context.Background()); err != nil {
		return nil, err
	}
	return b, nil
}

// Name is [Name].
func (b *Backend) Name() string { return Name }

// Rank is 10, above the software backends.
func (b *Backend) Rank() int { return rank }

// ConfinesProcess is true for a backend [New] made: New succeeds only inside
// a TD, so the process runs inside the backend's boundary. A Backend built
// any other way reports false.
func (b *Backend) ConfinesProcess() bool { return b.constructed }

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

package intelsgx

import (
	"context"
	"sync"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Name is the name the backend reports and is registered under.
const Name = "intel-sgx"

// rank is the backend's Detect rank: above locked memory (0) and
// linux-secretmem (1). Open question Q4, recommended option: rank 2, equal
// to the other TEE-memory proposals, since two of them do not meet in one
// process.
const rank = 2

// Backend is the intel-sgx backend. It exists only inside a non-debug SGX
// enclave that can quote: [New] refuses everywhere else.
type Backend struct {
	// constructed is set only by newBackend, so a Backend that New did not
	// build claims no confinement and refuses use.
	constructed bool

	// attestSem is a one-slot semaphore serializing [Backend.Attest]'s
	// request and check; a waiter selects on its context.
	attestSem chan struct{}

	// handlesMu guards handles, the live imported handles Sweep destroys.
	handlesMu sync.Mutex
	handles   map[*handle]struct{}
}

// newBackend returns a constructed Backend; only New and tests call it.
func newBackend() *Backend {
	return &Backend{constructed: true, attestSem: make(chan struct{}, 1)}
}

var (
	_ enclave.Prober   = (*Backend)(nil)
	_ enclave.Confiner = (*Backend)(nil)
)

// New returns the backend after running the same check as [Backend.Probe],
// so a backend that cannot attest is never built. Outside a usable enclave it
// returns an error matching [ErrSGXUnavailable]; a nil ctx is
// context.Background.
func New(ctx context.Context) (*Backend, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := probe(ctx); err != nil {
		return nil, err
	}
	return newBackend(), nil
}

// Name returns [Name].
func (*Backend) Name() string { return Name }

// Rank returns 2.
func (*Backend) Rank() int { return rank }

// Probe checks that this process is still in a non-debug SGX enclave that can
// quote, as [New] does. It returns ctx.Err() when ctx ends first, and an
// error matching [ErrSGXUnavailable] naming the failing step otherwise. A
// nil ctx is context.Background.
func (*Backend) Probe(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return probe(ctx)
}

// ConfinesProcess reports true for a Backend New built: New succeeds only
// inside a non-debug enclave, which holds the whole process. A Backend New
// did not build reports false.
func (b *Backend) ConfinesProcess() bool { return b.constructed }

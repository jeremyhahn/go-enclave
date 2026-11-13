package imxele

import (
	"context"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Name is the backend's registered name.
const Name = "imx-edgelock-enclave"

// rank is above arm-trustzone's 2 (docs/backends/imx-edgelock-enclave.md
// Q3, the recommended option): on the i.MX 95 both may probe usable, and the
// ELE keeps its keys out of the application cores' memory, secure world
// included.
const rank = 3

// Backend is the imx-edgelock-enclave backend. The zero value probes
// [DefaultEndpoint], so a main can register it for [enclave.Detect]; the
// probe runs only from Detect (Q4).
//
// This slice implements [enclave.Backend] and [enclave.Prober]. Importer,
// Sweeper and Attester, as "Shape proposed" lists them, follow once the
// session to trusted-imx95's trusted application exists; Confiner never,
// since the caller runs outside the secure world.
type Backend struct {
	endpoint string
}

var (
	_ enclave.Backend = (*Backend)(nil)
	_ enclave.Prober  = (*Backend)(nil)
)

// Connect constructs the backend on the TEE device at endpoint
// ([DefaultEndpoint] when empty), running the probe's check first.
// Construction never falls back to another backend: a refusal is returned as
// its typed error.
func Connect(endpoint string) (*Backend, error) {
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	b := &Backend{endpoint: endpoint}
	if err := b.Probe(context.Background()); err != nil {
		return nil, err
	}
	return b, nil
}

// Name returns [Name].
func (*Backend) Name() string { return Name }

// Rank returns the backend's detection rank, above arm-trustzone's.
func (*Backend) Rank() int { return rank }

// Probe checks that the backend is usable on this host and leaves nothing
// open behind it. Each refusal is a typed error naming its step.
func (b *Backend) Probe(ctx context.Context) error {
	return probe(ctx, b.endpoint)
}

// Connector constructs the backend for the conformance harness.
type Connector struct{}

// Name returns [Name].
func (Connector) Name() string { return Name }

// Connect constructs the backend on endpoint, as [Connect] does.
func (Connector) Connect(endpoint string) (enclave.Backend, error) {
	b, err := Connect(endpoint)
	if err != nil {
		return nil, err
	}
	return b, nil
}

package macse

import (
	"context"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Name is the backend's registered name.
const Name = "mac-secure-enclave"

// rank is the proposal's Q8, the recommended option: 2, the secure-element
// class, above locked memory (0) and secretmem (1).
const rank = 2

// The backend is a Prober now. The proposal's Attester and Sweeper join with
// the handles and attestation in later slices; it is never an Importer (the
// Secure Enclave imports nothing, so Sealed.OpenIn into it fails with the
// root's *CapabilityError before any work).
var _ enclave.Prober = (*Backend)(nil)

// Backend is the mac-secure-enclave backend. Build it with [New]; the zero
// value probes and reports its name and rank, and is how [enclave.Detect]
// sees it.
type Backend struct{}

// New runs the probe's check and returns the backend only if it passes, so a
// backend that cannot use the Secure Enclave is never built. Its error is the
// probe's: a [*SecurityError] or [*PlatformError] matching
// [ErrSecureEnclaveUnavailable], or ctx's own. A nil ctx never ends.
func New(ctx context.Context) (*Backend, error) {
	if err := probe(ctx); err != nil {
		return nil, err
	}
	return &Backend{}, nil
}

// Name returns "mac-secure-enclave".
func (*Backend) Name() string { return Name }

// Rank returns 2, the secure-element class.
func (*Backend) Rank() int { return rank }

// Probe reports whether the Secure Enclave is usable here: it creates one
// transient key, signs one digest with it and verifies the signature. It
// leaves nothing behind; the key goes with the call.
func (*Backend) Probe(ctx context.Context) error { return probe(ctx) }

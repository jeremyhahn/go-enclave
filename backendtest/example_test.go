package backendtest_test

import (
	"context"
	"crypto/rand"
	"fmt"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/backendtest"
)

// ExampleTestBackend runs the conformance suite against the shipped
// locked-memory backend. A backend author writes the same Config for their
// own backend: a constructor, exactly the capabilities the backend claims,
// and one case per kind of handle it makes.
func ExampleTestBackend() {
	cfg := backendtest.Config{
		New: func() (enclave.Backend, error) { return enclave.DefaultBackend(), nil },
		// The locked-memory backend is a Prober and nothing more: it imports
		// nothing, so its handles come from the package constructors.
		BackendCapabilities: []enclave.Capability{enclave.CapabilityProbe},
		Handles: []backendtest.HandleCase{{
			Name: "locked-region",
			// The material is random: the residue sweep looks for it byte for
			// byte, and zeros are everywhere in a process.
			New: func(context.Context, enclave.Backend) (enclave.Handle, error) {
				m, err := enclave.NewMemorySized(32)
				if err != nil {
					return nil, err
				}
				if err := m.WithBytes(func(b []byte) error {
					_, err := rand.Read(b)
					return err
				}); err != nil {
					_ = m.Destroy()
					return nil, err
				}
				return m, nil
			},
			Capabilities: []enclave.Capability{enclave.CapabilityBytes, enclave.CapabilityFreeze},
		}},
	}
	if err := backendtest.TestBackend(context.Background(), cfg); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("locked-memory backend conforms")
	// Output: locked-memory backend conforms
}

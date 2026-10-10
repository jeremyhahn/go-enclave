// Package backendtest checks that a backend implementation honors the enclave
// backend seam.
//
// A backend author supplies a Config whose New function returns a fresh backend
// and whose handle cases describe the handles that backend can make. TestBackend
// checks the core Handle lifecycle, exact capability claims, context refusal,
// concurrent use under the race detector, and the contract of every capability
// the backend and its cases declare: ByteAccess, Freezer, Deriver,
// crypto.Signer, crypto.Decrypter, AEAD, Attester, Importer, Sweeper and
// Confiner, each in normal use and, for a handle, again after Destroy. On
// Linux it also sweeps the process for a handle's material after Destroy and,
// for a Sweeper, after Sweep.
//
// A declared capability whose contract the suite cannot exercise is refused
// with an [*UncheckedCapabilityError], never passed. An Attester is one such
// capability unless Config.VerifyEvidence is set: only the attestation's
// relying party can tell evidence that binds the nonce from evidence that
// merely differs between calls. The full list of checks is in
// docs/backends/architecture.md, "What it checks".
//
//	func TestBackendConformance(t *testing.T) {
//		err := backendtest.TestBackend(t.Context(), backendtest.Config{
//			New: func() (enclave.Backend, error) { return mybackend.Open() },
//			BackendCapabilities: []enclave.Capability{
//				enclave.CapabilityImport,
//			},
//			Handles: []backendtest.HandleCase{{
//				Name:       "material",
//				Import:     []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)},
//				ImportSize: 32,
//				Capabilities: []enclave.Capability{
//					enclave.CapabilityBytes,
//				},
//			}},
//			Logf: t.Logf,
//		})
//		if err != nil {
//			t.Fatal(err)
//		}
//	}
package backendtest

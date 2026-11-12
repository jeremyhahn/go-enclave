// Package intelsgx is the intel-sgx backend: a go-enclave backend for a
// process that runs whole inside an Intel SGX enclave under a library OS
// (Gramine), as docs/backends/intel-sgx.md proposes.
//
// The backend reaches SGX only through the library OS's /dev/attestation
// pseudo-filesystem, which exists inside the enclave only (open question Q3,
// recommended option: the library OS's interface, no cgo and no SDK). It is
// built with [New], which runs the same check as [Backend.Probe]: the process
// is in a non-debug enclave whose attestation type is DCAP and which can
// produce a version 3 ECDSA quote over a fresh nonce. Outside such an enclave
// New and Probe return an error matching [ErrSGXUnavailable] whose
// [*SGXEnclaveError] names the failing step.
//
// The module requires go-enclave, never the reverse, and nothing registers it
// at import: main registers the backend it built. It is built for linux/amd64;
// on any other GOOS or GOARCH a stub compiles whose constructor and probe
// return [ErrSGXUnavailable], so a cross-platform main that registers it
// builds everywhere.
//
// This first slice carries the module, the typed errors, the probe and the
// refusal path. Attest, Import, Sweep and the handles follow in later slices
// (docs/plans/193.md).
package intelsgx

// Package macse is go-enclave's mac-secure-enclave backend: P-256 keys held
// in the Apple Secure Enclave of a Mac with Apple silicon or a T2 chip,
// reached through the Security framework
// (docs/backends/mac-secure-enclave.md).
//
// It is a module of its own, in the shape of backends/armtrustzone (the
// proposal's Q1, the recommended option): it requires go-enclave, never the
// reverse, and nothing registers it at import; main calls [New] and
// registers the backend it returns.
//
// The backend runs on darwin only. This slice carries no Security framework
// binding yet: on every build, darwin included, [New] and [Backend.Probe]
// return a [*PlatformError] matching [ErrSecureEnclaveUnavailable], naming
// the create step. The next slice adds the cgo binding (the proposal's Q2,
// the recommended option) in a darwin-and-cgo file, built and proven on a
// physical Mac; no simulator stands in for it.
package macse

// Package amdsev is the amd-sev backend: go-enclave inside an AMD SEV-SNP
// guest, attested by the SNP firmware's ATTESTATION_REPORT through the Linux
// configfs-tsm report interface (/sys/kernel/config/tsm/report, provider
// sev_guest). docs/backends/confidential-vm.md is its design.
//
// It is a module of its own, out of the go-enclave tree's root module: it
// depends on go-enclave and golang.org/x/sys, never the reverse, and nothing
// registers it at import; main registers it explicitly with [enclave.Register]
// or injects it.
//
// It runs on Linux on amd64 only. On every other GOOS or GOARCH it compiles,
// so a cross-platform main that names it builds everywhere, but [New] and
// [Backend.Probe] return [ErrSNPGuestUnavailable].
//
// Handles are memory enclaves made with [enclave.NewMemory] inside the guest,
// whose private memory the SNP firmware encrypts with the guest's key; they
// provide [enclave.ByteAccess] and [enclave.Freezer]. The backend provides
// [enclave.Importer], [enclave.Attester], [enclave.Confiner],
// [enclave.Sweeper] and [enclave.Prober] (rank 2). Construction and the probe
// both request one report over a fresh nonce, so a backend that cannot attest
// is never built.
//
// The backend is also an [enclave.RootUnsealer]: [Backend.UnsealRoot] asks
// the firmware, through /dev/sev-guest's SNP_GET_DERIVED_KEY, for a key from
// the chip's VCEK bound to the guest's policy and launch measurement, so a
// root sealed under it opens only for the same guest on the same chip.
//
// The package never verifies evidence: [ParseReport] reads the few fields
// the probe checks, and the relying party's verifier checks the signature,
// the certificate chain and its policy.
package amdsev

### Added

- **The `mac-secure-enclave` backend's design is proposed in [docs/backends/mac-secure-enclave.md](docs/backends/mac-secure-enclave.md)** (#192): a darwin-only secure-element backend whose handles are P-256 signers in the Secure Enclave, attested through Managed Device Attestation, proven on a physical Mac, and eight questions open for a ruling. Nothing changes for Go callers.

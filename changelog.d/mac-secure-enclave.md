### Added

- **mac-secure-enclave**: the design of a darwin-only backend whose handles are P-256 signers in the Mac Secure Enclave is proposed in [docs/backends/mac-secure-enclave.md](docs/backends/mac-secure-enclave.md) (#192).
- **mac-secure-enclave**: the `backends/macse` module begins with typed errors, the probe and `New`, `Name` and `Rank`, and until the darwin binding lands `New` and `Probe` refuse with `ErrSecureEnclaveUnavailable` on every platform (#192).

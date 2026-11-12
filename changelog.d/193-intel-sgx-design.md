### Added

- **The `intel-sgx` backend's design is proposed in [docs/backends/intel-sgx.md](docs/backends/intel-sgx.md)** (#193): a Go program running whole inside an SGX enclave under a library OS, attesting with a DCAP ECDSA quote, its failure modes, a test plan on real hardware, and ten decisions open for a ruling. The SPEC row moves from `future` to `planned`. Nothing changes for Go callers.

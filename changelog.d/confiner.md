### Added

- **confiner**: The Intel SGX backend's design is proposed in [docs/backends/intel-sgx.md](docs/backends/intel-sgx.md), and its own Go module starts at `backends/intelsgx` with typed errors and `New` and `Probe`, which refuse outside a non-debug SGX enclave that can quote.
- **confiner**: `Import` and `Sweep` keep material in a memory enclave inside the SGX enclave; the backend implements no `Attester`, since attestation is go-xkms's.
- **confiner**: `Probe` refuses a `Backend` that `New` did not build, so detection never selects an instance whose `Import` refuses.

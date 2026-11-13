### Added

- **intel-sgx**: The backend's design is proposed in [docs/backends/intel-sgx.md](docs/backends/intel-sgx.md), and its own Go module starts at `backends/intelsgx` with typed errors and `New` and `Probe`, which refuse outside a non-debug SGX enclave that can quote. ([#193](https://github.com/jeremyhahn/go-enclave/issues/193))
- **intel-sgx**: `Backend.Attest(ctx, nonce)` returns `Evidence{Format: "sgx-quote"}`, a version 3 ECDSA quote over the nonce, and `Import` and `Sweep` keep material in a memory enclave inside the SGX enclave. ([#193](https://github.com/jeremyhahn/go-enclave/issues/193))
- **intel-sgx**: `Probe` refuses a `Backend` that `New` did not build, so detection never selects an instance whose `Import` and `Attest` refuse. ([#193](https://github.com/jeremyhahn/go-enclave/issues/193))

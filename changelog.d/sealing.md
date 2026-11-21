### Changed

- **BREAKING** sealing: the exported type `armtrustzone.KeyProtector`, with its methods `Protect`, `Unprotect` and `Health`, and the method `(*armtrustzone.Backend).KeyProtector()` that returned it are removed; seal with `SoftwareProvider` or inject another `KeyProtector`. See [Upgrading](docs/README.md#upgrading).
- **BREAKING** sealing: the nested module `github.com/jeremyhahn/go-enclave/backends/tpm`, which shipped in v0.12.0-alpha, is removed, and its TPM `KeyProtector` provider is no longer part of this repository. See [Upgrading](docs/README.md#upgrading).

### Changed

- **BREAKING** sealing: the hardware `KeyProtector` providers, the nested module `github.com/jeremyhahn/go-enclave/backends/tpm` and `(*armtrustzone.Backend).KeyProtector()`, are removed, and their callers move to [go-xkms](https://github.com/jeremyhahn/go-xkms) or seal with `SoftwareProvider`. See [Upgrading](docs/README.md#upgrading).

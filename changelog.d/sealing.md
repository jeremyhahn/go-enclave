### Changed

- **BREAKING** sealing: the hardware `KeyProtector` providers are removed: the nested module `github.com/jeremyhahn/go-enclave/backends/tpm` and `(*armtrustzone.Backend).KeyProtector()`. Their callers move to [go-xkms](https://github.com/jeremyhahn/go-xkms) or seal with `SoftwareProvider`; the `KeyProtector` interface, `SoftwareProvider`, `providertest` and the arm-trustzone backend are unchanged. See [Upgrading](docs/README.md#hardware-keyprotector-providers-removed).

### Changed

- **The secure-element provider's open questions 8-11 carry proposed answers in [docs/sealing/hardware-providers.md](docs/sealing/hardware-providers.md#open-questions)** (#264): a pure-Go PKCS#11 loader in the nested `backends/pkcs11` module, SoftHSM as the CI fixture, a caller-supplied random GCM nonce with the usage limit left to the operator, and operator-provisioned keys with the user PIN handed in by the caller. They await the owner's sign-off. Nothing changes for Go callers.

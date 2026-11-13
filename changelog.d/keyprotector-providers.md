### Added

- **keyprotector-providers**: `backends/tpm` gains `FuzzParseBlob`, a native Go fuzz target that holds the sealed-blob parser to its contract on arbitrary input, with no TPM: it never panics or writes the blob, a refusal matches `ErrSealedAuthentication`, and an accepted blob is exactly the framing of its sealed-object public area and bounded private area (#336).

### Changed

- **keyprotector-providers**: the secure-element provider's open questions 8-11 in [docs/sealing/hardware-providers.md](docs/sealing/hardware-providers.md#open-questions) carry proposed answers awaiting the owner's sign-off (#264): a pure-Go PKCS#11 loader in the nested `backends/pkcs11` module, SoftHSM as the CI fixture, a caller-supplied random GCM nonce with the usage limit left to the operator, and operator-provisioned keys with the user PIN handed in by the caller; nothing changes for Go callers.

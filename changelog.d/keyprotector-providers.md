### Added

- **keyprotector-providers**: `backends/tpm` gains `FuzzParseBlob`, a native Go fuzz target that holds the sealed-blob parser to its contract on arbitrary input, with no TPM: it never panics or writes the blob, a refusal matches `ErrSealedAuthentication`, and an accepted blob is exactly the framing of its sealed-object public area and bounded private area (#336).
- **keyprotector-providers**: `backends/tpm`: malformed-response tables and the `FuzzExecuteResponse`, `FuzzCut2B` and `FuzzListType` fuzz targets, with seed corpora, for the TPM command-response path; a test proves the transport never hands the parser less than the response header (#346).
- **keyprotector-providers**: `backends/tpm` holds every error type and `Err...` sentinel to one contract table: the message carries the package prefix on zero and populated values, `errors.Is` matches only the type's own sentinels, `errors.As` finds the type through `%w` and `errors.Join`, `Unwrap` exposes the cause, and no byte field reaches a message; a source check fails on any exported error type or sentinel without a row (#371).
- **keyprotector-providers**: `docs/reference/` now carries the TCG standards the TPM provider implements: TPM 2.0 Library Parts 1–3 at revision 01.59 and the TCG EK Credential Profile 2.7, whose storage template shapes the provider's parent, each indexed with its sha256; `docs/sealing/hardware-providers.md` links them where it cites them (#335). Nothing changes for Go callers.

### Changed

- **keyprotector-providers**: the secure-element provider's open questions 8-11 in [docs/sealing/hardware-providers.md](docs/sealing/hardware-providers.md#open-questions) carry proposed answers awaiting the owner's sign-off (#264): a pure-Go PKCS#11 loader in the nested `backends/pkcs11` module, SoftHSM as the CI fixture, a caller-supplied random GCM nonce with the usage limit left to the operator, and operator-provisioned keys with the user PIN handed in by the caller; nothing changes for Go callers.

### Fixed

- **keyprotector-providers**: `backends/tpm`: a response to an authorized command with bytes after its authorization area is now refused as malformed instead of accepted (#346).
- **keyprotector-providers**: `backends/tpm`: listing the device's handles takes each handle once, in ascending order, so a device that repeats a page can no longer list the same handle many times over (#346).
- **keyprotector-providers**: `backends/tpm`'s `DeviceError.Error` and `CommandError.Error` no longer panic when `Err` is nil (#371).

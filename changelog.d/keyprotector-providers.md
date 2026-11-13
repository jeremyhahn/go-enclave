### Added

- **keyprotector-providers**: `backends/tpm` gains `FuzzParseBlob`, a native Go fuzz target that holds the sealed-blob parser to its contract on arbitrary input, with no TPM: it never panics or writes the blob, a refusal matches `ErrSealedAuthentication`, and an accepted blob is exactly the framing of its sealed-object public area and bounded private area (#336).
- **keyprotector-providers**: `backends/tpm`: malformed-response tables and the `FuzzExecuteResponse`, `FuzzCut2B` and `FuzzListType` fuzz targets, with seed corpora, for the TPM command-response path; a test proves the transport never hands the parser less than the response header (#346).

### Fixed

- **keyprotector-providers**: `backends/tpm`: a response to an authorized command with bytes after its authorization area is now refused as malformed instead of accepted (#346).
- **keyprotector-providers**: `backends/tpm`: listing the device's handles takes each handle once, in ascending order, so a device that repeats a page can no longer list the same handle many times over (#346).

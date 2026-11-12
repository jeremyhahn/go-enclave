### Added

- `backends/tpm`: malformed-response tables and the `FuzzExecuteResponse` and `FuzzCut2B` fuzz targets, with seed corpora, for the TPM command-response path; a test proves the transport never hands the parser less than the response header (#346).

### Fixed

- `backends/tpm`: a response to an authorized command with bytes after its authorization area is now refused as malformed instead of accepted (#346).
- `backends/tpm`: listing the device's handles takes each handle once, in ascending order, so a device that repeats a page can no longer list the same handle many times over (#346).

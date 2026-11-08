### Added

- `make integration-test-tpm` runs the TPM provider's conformance suite (residue sweep included) and its sealed-blob length check against a throwaway swtpm on loopback (`SWTPM_PORT`, `SWTPM_CTRL_PORT`); CI's `tpm-swtpm` job runs it on the full tier (on a pull request, when the TPM paths change)

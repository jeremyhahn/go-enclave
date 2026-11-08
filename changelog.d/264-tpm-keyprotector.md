### Added

- `backends/tpm`, a separate module with a TPM 2.0 `enclave.KeyProtector` for Linux: `tpm.Open("")` opens `/dev/tpmrm0`, and `Protect` seals each key in a TPM sealed-data object under a transient, label-bound storage parent, so the blob opens only on the TPM that sealed it; a foreign or altered blob fails with `ErrSealedAuthentication`, and cancellation flushes every transient handle and wipes every key transient before returning (#264).

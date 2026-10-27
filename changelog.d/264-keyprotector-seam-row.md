### Changed

- **docs: the KeyProtector provider seam is a planned row.** `docs/SPEC.md` and `ROADMAP.md` gain `keyprotector-providers`: what go-enclave owns, the four planned `KeyProtector` providers (memory, TrustZone, secure element, TPM), the named consumers (go-xkms's `EnclaveBackend`, trusted-firmware's TA), the ruling still pending on TPM and secure element, and the open item that no document yet defines the blob contract normatively. Nothing changes for Go callers.

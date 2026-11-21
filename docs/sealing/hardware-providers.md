# Hardware KeyProtector providers — removed

> **Status: REFERENCE** · Scope: go-enclave · Last verified: 2026-11-21
> A record of where the hardware `KeyProtector` providers went. No code in this repository implements them.

go-enclave ships no hardware `KeyProtector` provider. Its scope is the
protected-memory primitives, the sealing envelope and the
[`KeyProtector` seam](engineering.md#provider-contract), with one provider
behind it: memory (`SoftwareProvider`). A provider over a device belongs to a
crypto library above go-enclave
([key-operation API removal](../SPEC.md#key-operation-api-removal)).

Two hardware providers used to ship here, and both were removed:

- **TPM 2.0**: a nested module of its own (`tpm.Open`, sealing a data
  key under a TPM storage key). It now lives in
  [go-xkms](https://github.com/jeremyhahn/go-xkms).
- **TrustZone**: `(*armtrustzone.Backend).KeyProtector`, over the OP-TEE
  trusted application's SEAL and UNSEAL commands. It also lives in go-xkms.
  The arm-trustzone backend itself stays in go-enclave
  ([arm-trustzone design](../backends/arm-trustzone-design.md)).

The secure-element (PKCS#11) provider outline that this page used to hold was
never implemented in go-enclave; it belongs to go-xkms as well.

Callers migrate as the [Upgrading notes](../README.md#upgrading) describe:
move to go-xkms, or seal with `SoftwareProvider`. No sealed value needs
converting: a `Sealed` lives only in the memory of the process that sealed it.

## Open questions

None. The questions this page held about the hardware providers were closed
by their removal; the providers, and any question about them, now belong to
[go-xkms](https://github.com/jeremyhahn/go-xkms).

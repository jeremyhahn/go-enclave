# Hardware KeyProtector providers — removed

> **Status: REFERENCE** · Scope: go-enclave · Last verified: 2026-11-24
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
  [go-xkms](https://github.com/jeremyhahn/go-xkms):
  `enclaveprovider.NewKeyProtector` in the package
  `github.com/jeremyhahn/go-xkms/pkg/enclaveprovider`, over go-xkms's TPM 2.0
  sealer.
- **TrustZone**: `(*armtrustzone.Backend).KeyProtector`, over the OP-TEE
  trusted application's SEAL and UNSEAL commands. It also lives in go-xkms:
  the same `enclaveprovider.NewKeyProtector`, over go-xkms's OP-TEE sealer.
  The arm-trustzone backend itself stays in go-enclave
  ([arm-trustzone design](../backends/arm-trustzone-design.md)).

The secure-element (PKCS#11) provider outline that this page used to hold was
never implemented in go-enclave; it belongs to go-xkms as well.

## Secure-element provider: decided design

The secure-element provider is built in
[go-xkms](https://github.com/jeremyhahn/go-xkms); go-enclave gains no module,
dependency or code for it. Its design is recorded here so that the decisions
on its open questions are not lost.

**Shape.**

- **Key:** one AES-256 secret key in the token, with `CKA_TOKEN`,
  `CKA_SENSITIVE`, `CKA_ENCRYPT` and `CKA_DECRYPT` true and `CKA_EXTRACTABLE`
  false, found by its `CKA_ID`. The provider uses the key and never reads it.
- **Protect:** `C_EncryptInit` with `CKM_AES_GCM` (a 96-bit nonce, a 128-bit
  tag, the label `go-enclave v1 PKCS#11 KeyProtector` as AAD), then
  `C_Encrypt` of the key.
- **Unprotect:** `C_DecryptInit` and `C_Decrypt` into a locked transient,
  copied out only when the tag verified and the length is right. A tag
  failure, an unknown `CKA_ID`, a wrong version byte and a malformed blob
  match `ErrSealedAuthentication`.

| Offset | Length | Field |
| --- | --- | --- |
| 0 | 1 | version = 1 |
| 1 | 1 | k: length of the key's `CKA_ID` |
| 2 | k | the key's `CKA_ID` |
| 2 + k | 12 | GCM nonce |
| 14 + k | n + 16 | ciphertext of the n-byte key, then the GCM tag |

**Decisions.**

- **cgo:** a pure-Go PKCS#11 loader in the provider's own package in go-xkms,
  so the provider builds with `CGO_ENABLED=0`. A helper process is rejected:
  the key would cross an IPC boundary the provider does not control. A cgo
  binding is rejected: it brings a C toolchain into the static and cross
  builds.
- **Test fixture:** SoftHSM v2, at its latest release, in a CI fixture job
  that runs `providertest` with its residue sweep and no skip, as `swtpm` did
  for the TPM provider. The suite asserts the contract and the blob layout,
  not token-specific GCM behaviour.
- **Nonce and limits:** a random 96-bit nonce from `crypto/rand`. The 2^32
  encryption limit per key (NIST SP 800-38D) is the operator's, met by
  provisioning a new key under a new `CKA_ID`; old blobs still open because
  each names its key. The provider keeps no cross-process state.
- **Key provisioning and login:** an operator provisions the key; the
  provider never creates one, and refuses a key that is extractable or not
  sensitive. The caller passes the user PIN in a locked buffer that the
  provider wipes after `C_Login`; a token with a protected authentication
  path logs in with no PIN. No credential enters the provider's
  configuration.

**Not decided here.** go-xkms chooses which hardware token, if any, gets a
recurring CI run, and whether FIPS-mode tokens that refuse a caller-supplied
nonce are a target of the first slice.

Callers migrate as the [Upgrading notes](../README.md#upgrading) describe:
move to go-xkms, or seal with `SoftwareProvider`. No sealed value needs
converting: a `Sealed` lives only in the memory of the process that sealed it.

## Open questions

None. The questions this page held about the hardware providers were closed
by their removal; the providers, and any question about them, now belong to
[go-xkms](https://github.com/jeremyhahn/go-xkms).

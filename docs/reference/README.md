# Reference standards

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-31
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

Standards first: where a standard exists, go-enclave implements it as written
and designs nothing in its place. Each standard the code implements is copied
here; a draft is adopted at one pinned revision and watched
(the handbook's `software/conventions/documentation.md` §9).
go-enclave implements no draft.

| File | Title | Revision | Implemented by |
|---|---|---|---|
| [NIST.FIPS.197-upd1.pdf](NIST.FIPS.197-upd1.pdf) | Advanced Encryption Standard (AES) | FIPS 197, November 2001, updated May 2023 | `enclave`: `withAEAD` ([aead.go](../../aead.go)), AES-256 under a 32-byte key (`RootKeyBytes`, `kekBytes`) |
| [NIST.SP.800-38D.pdf](NIST.SP.800-38D.pdf) | Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC | SP 800-38D, November 2007 | `enclave`: `withAEAD`, `sealWithKey`, `openWithKeyInto` ([aead.go](../../aead.go)), 96-bit random nonce and 128-bit tag; `wrapKey`, `unwrapKey` ([keywrap.go](../../keywrap.go)); the §8.3 invocation bound, halved, in `kekMessageLimit` ([hierarchy.go](../../hierarchy.go)) and `softwareProtectLimit` ([provider_software.go](../../provider_software.go)) |
| [rfc5869.txt](rfc5869.txt) | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | RFC 5869, May 2010 | `enclave`: `deriveWrappingKey` ([hierarchy.go](../../hierarchy.go)), salt and `wrappingKeyInfo`; `deriveProtectKey` ([provider_software.go](../../provider_software.go)), `softwareProtectKeyInfo` |
| [NIST.FIPS.180-4.pdf](NIST.FIPS.180-4.pdf) | Secure Hash Standard (SHS) | FIPS 180-4, August 2015 | `enclave`: SHA-256 as the HKDF hash in `deriveWrappingKey` and `deriveProtectKey` |
| [NIST.FIPS.140-3.pdf](NIST.FIPS.140-3.pdf) | Security Requirements for Cryptographic Modules | FIPS 140-3, March 2019 | `enclave`: sealing uses only approved algorithms and runs under Go's FIPS 140-3 module in strict mode, `make test-fips` ([FIPS 140-3](../sealing/engineering.md#fips-140-3)) |
| [rfc9562.txt](rfc9562.txt) | Universally Unique IDentifiers (UUIDs) | RFC 9562, May 2024 | `armtrustzone`: `parseUUID` and `teecUUID.octets` ([client.go](../../backends/armtrustzone/client.go)), the TA UUID's text form and its network-order octets |
| [linux-uapi-tee.h](linux-uapi-tee.h) | Linux TEE subsystem user API, `include/uapi/linux/tee.h` | linaro-swg/linux tag `optee-4.11.0` (commit `cf6e3218c25183cbc45551e85d0dd531f00fcc3d`), the kernel OP-TEE 4.11.0's `qemu_v8.xml` manifest pins | `armtrustzone`: the ioctl structs and numbers in [tee_linux.go](../../backends/armtrustzone/tee_linux.go), used by [client_linux.go](../../backends/armtrustzone/client_linux.go) |
| [TCG_TPM2_r1p59_Part1_Architecture_pub.pdf](TCG_TPM2_r1p59_Part1_Architecture_pub.pdf) | Trusted Platform Module Library, Part 1: Architecture | Family 2.0, Level 00, Revision 01.59, November 2019 (see [TCG TPM 2.0](#tcg-tpm-20)); sha256 `18e393ef8f61d4c5deebb578cc4220b025fdaff2c28a7e3264f16e37796c3d9b` | `tpm`: the salted, parameter-encrypted session in `startSession` ([protector.go](../../backends/tpm/protector.go)) and the `KDFa` and CFB parameter encryption it relies on |
| [TCG_TPM2_r1p59_Part2_Structures_pub.pdf](TCG_TPM2_r1p59_Part2_Structures_pub.pdf) | Trusted Platform Module Library, Part 2: Structures | Family 2.0, Level 00, Revision 01.59, November 2019; sha256 `95b27445c8a3302bffaf0eed0e729f228698d0296a91161f51320fbe4d7c5121` | `tpm`: `TPMT_PUBLIC` in `parentTemplate`, `storageTemplate` ([blob.go](../../backends/tpm/blob.go)); the format-one response codes the error mapping reads |
| [TCG_TPM2_r1p59_Part3_Commands_pub.pdf](TCG_TPM2_r1p59_Part3_Commands_pub.pdf) | Trusted Platform Module Library, Part 3: Commands | Family 2.0, Level 00, Revision 01.59, November 2019; sha256 `d2e5e7187574d383b00ff966c33b30a96e3f5165cbfae20a4d094e5794f3b9bb` | `tpm`: `TPM2_Create` in `create` and `TPM2_Unseal` in `unseal` ([unseal.go](../../backends/tpm/unseal.go)), marshaled by the provider; `TPM2_CreatePrimary`, `TPM2_StartAuthSession`, `TPM2_Load`, `TPM2_FlushContext` in `createPrimary`, `startSession`, `load`, `flush` ([protector.go](../../backends/tpm/protector.go)) |
| [TCG_EK_Credential_Profile_for_TPM_Family_2_0_Level_0_Version_2_7_Pub.pdf](TCG_EK_Credential_Profile_for_TPM_Family_2_0_Level_0_Version_2_7_Pub.pdf) | TCG EK Credential Profile for TPM Family 2.0; Level 0 | Version 2.7, March 16, 2026 (see [TCG TPM 2.0](#tcg-tpm-20)); sha256 `b021106be50d5f391064ef702ca5f98249b614a90f2672931f45b79b2f441c2f` | `tpm`: the parent's template in `parentTemplate` and `storageTemplate` ([blob.go](../../backends/tpm/blob.go)), §5.3.4 Template L-2: ECC NIST P256 (Storage), with `unique.x` set from the label |

## TCG TPM 2.0

The TPM provider follows the TPM 2.0 Library at revision 01.59. The provider
builds on `github.com/google/go-tpm` v0.9.8 (`backends/tpm/go.mod`), whose
`tpm2` package defines no command code after `TPM_CC_ACT_SetTimeout`
(0x00000198) and none that revision 1.83 adds, and every command the provider
sends is defined at 01.59.

The copies are the publisher's files, as published at
<https://trustedcomputinggroup.org/resource/tpm-library-specification/>,
renamed to drop the download suffix; a later reader verifies each against the
sha256 in its row. Their licence (each document's "Licenses and Notices",
page ii) grants the rights to reproduce, distribute, display and perform the
specification for the purpose of developing products based on it, which is
the purpose of these copies.

The parent's template is the storage template of the EK credential profile,
§5.3.4 Template L-2: ECC NIST P256 (Storage), at the profile's latest
version, 2.7, which this index pins. The copy is
the publisher's file from
<https://trustedcomputinggroup.org/resources/documents/http-trustedcomputinggroup-org-wp-content-uploads-tcg-ek-credential-profile>,
renamed to drop the download suffix. Its licence (page ii, "Disclaimers,
Notices, and License Terms") permits a copy for examining or implementing TCG
specifications, distributed with its disclaimers; the file is unaltered and
carries them.

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

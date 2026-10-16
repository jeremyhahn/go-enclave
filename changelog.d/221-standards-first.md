### Added

- **Standards first: `docs/reference/` copies each standard the code implements** (#221). FIPS 197 (AES), SP 800-38D (GCM), RFC 5869 (HKDF), FIPS 180-4 (SHA-256) and FIPS 140-3, indexed in [docs/reference/README.md](docs/reference/README.md) with the implementing symbol. go-enclave implements no draft. Nothing changes for Go callers.

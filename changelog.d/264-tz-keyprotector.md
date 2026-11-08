### Added

- **The `arm-trustzone` backend module has a TrustZone `KeyProtector`**: `(*Backend).KeyProtector()` returns an `enclave.KeyProtector` and `enclave.HealthReporter` that seals keys with the OP-TEE trusted application's SEAL command and opens them with UNSEAL, under a fixed associated-data label; a tampered blob or a length mismatch fails with `enclave.ErrSealedAuthentication`.

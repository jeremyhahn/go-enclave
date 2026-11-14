### Added

- **arm-trustzone**: `KeyProtector.Unprotect` has a fuzz target, `FuzzKeyProtectorUnprotect`, that drives arbitrary blobs, key lengths and ended contexts through the client, shared-memory and driver path over the fake TEE. Only the untouched sealed blob opens; every other input fails with `enclave.ErrSealedAuthentication` and a zeroed key, and nothing is left open. ([#337](https://github.com/jeremyhahn/go-enclave/issues/337))

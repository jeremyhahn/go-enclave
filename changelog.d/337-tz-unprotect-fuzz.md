### Added

- **The TrustZone `KeyProtector.Unprotect` has a fuzz target over the fake TEE**: `FuzzKeyProtectorUnprotect` in the `arm-trustzone` backend module drives arbitrary blobs, key lengths and live, canceled or expired contexts through `Unprotect`, and the client, shared-memory and driver path under it, with both drivers and no TEE device; only the untouched sealed blob opens, every other input fails with `enclave.ErrSealedAuthentication` and a zeroed key, an ended context returns its error before any UNSEAL, and no shared memory, session or device fd is left open.

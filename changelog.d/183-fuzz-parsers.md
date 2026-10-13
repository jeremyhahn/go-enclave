### Added

- **Fuzz targets for the parsers of untrusted blobs** (#183). `FuzzSoftwareProviderUnprotect`, `FuzzSoftwareProviderRoundTrip`, `FuzzUnwrapKey` and `FuzzOpenWithKeyInto` feed the root package's protected-key, wrapped-key and sealed-payload parsers bytes go-enclave did not produce. They check that a parser never panics, that it refuses every such input with `ErrSealedAuthentication` (or `ctx.Err()` for an ended context), and that it leaves the destination untouched or wiped, never partly written. The Batch workflow's fuzz job now has targets to run.
- **Fuzz targets for the device-key unwrap path** (#183). `FuzzUnwrapKeyDevice` and `FuzzOpenOnDeviceInto` cover a wrapping key that encrypts in its device, at every nonce size, through an honest and a misbehaving fake key: a plaintext returned outside the destination is refused with `ErrPlaintextEscaped` and wiped, one of the wrong length with `ErrSealedAuthentication`, and a device failure is an `*OpenError`; every refusal leaves the destination untouched or wiped.

### Fixed

- **A refused unwrap through a device key wiped nothing** (#183). When a wrapping key that encrypts in its device opened into the destination and the unwrap was then refused (wrong length, escaped plaintext, device error), the destination kept what the device wrote, which could be the key itself. Every refusal after the device's `Open` now wipes the destination; the software path's AEAD open does the same. See [sealing invariant 1](docs/sealing/engineering.md#invariants).

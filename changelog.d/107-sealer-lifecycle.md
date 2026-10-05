### Added

- **`(*Sealer).Destroy() error` and `(*SoftwareProvider).Destroy() error`**
  (#107) release a sealer's keys (wrapping key, current KEK, retained KEK
  blobs, any pending root) and the default provider `NewSealer` created,
  never an injected one. Afterwards every seal, open and `Openable` reports the
  new `ErrSealerDestroyed`, so retired sealers no longer hold locked memory
  until `RLIMIT_MEMLOCK` runs out.
- **`GoString` on `SealedEnclave` and `MemoryEnclave`** (#107): `%#v` prints
  the same redacted form as `%v` instead of the ciphertext and wrapped key.

### Fixed

- **A zero-value `Sealer` no longer panics or blocks** (#107): `Seal` and
  `Open` return the new `ErrSealerNotConstructed` and still wipe the input.
- **The blob a `KeyProtector.Protect` returns is copied** (#107), so a
  provider that reuses its buffer no longer corrupts sealed values, and
  destroying a value no longer zeroes the provider's slice.
- **Material whose sealed length would overflow `int` is refused** (#107) with
  `ErrMaterialTooLarge` instead of panicking in AES-GCM, which on 32-bit
  platforms was reachable at about 2 GiB.

### Security

- **Corrected docs that overstated dump and swap protection** (#107): in
  `ModeRootKey` the KEK's AES key schedule reaches the ordinary heap on every
  seal and open, and the per-value DEK's in every mode, unless built with
  `GOEXPERIMENT=runtimesecret`.

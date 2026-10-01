### Added

- **`WithKEKRotationLimit(n)` sets a KEK generation's crypto-period** (#99):
  how many DEKs one generation wraps before a `ModeRootKey` sealer rotates.
  `n` must be between 1 and 2^31 (the package's safe bound, half of the 2^32
  `crypto/cipher` allows a random-nonce GCM key); zero, larger values, or the
  option given for `ModePerOperation` are refused by `NewSealer` with the new
  `ErrInvalidRotationLimit`. Every retired generation's blob is retained, so
  values sealed under any generation keep opening. A sealer wraps at most 2^31
  generations; a seal that would need one more is refused with the new
  `ErrSealerExhausted` (joined with `ErrSealFailed`), leaving every existing
  value openable.

### Changed

- **A `ModeRootKey` sealer wraps under a key derived from the root** (#99),
  never the provider's root itself: HKDF-SHA256 under a 256-bit salt drawn
  per sealer. Sealers sharing a provider, and restarts unsealing the same
  hardware root, no longer share one random-nonce GCM key, so the per-sealer
  usage bounds hold for the key they count. Sealed values never outlive their
  sealer, so nothing persisted changes.

### Changed — BREAKING: `Open` and `OpenWith` return read-only plaintext

- **The enclave `SealedEnclave.Open` and `OpenWith` return is frozen** (#99),
  like every other constructor whose material is final: a stray write through
  a retained slice faults instead of silently corrupting the plaintext. Code
  that wrote into an opened enclave must copy into its own sized enclave
  instead. A refused freeze fails the open closed (no enclave; the
  destination is wiped) rather than returning writable plaintext. `OpenWith`'s
  reservation is returned with the destination's pages; if the kernel also
  refuses that release, the charge stays until `WipeAll` reclaims them.

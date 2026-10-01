### Added

- **AES key schedules are erased under `runtime/secret`** (#98). Built with
  `GOEXPERIMENT=runtimesecret` for linux/amd64 or linux/arm64 (not Android), every AES
  operation runs under `runtime/secret.Do`, so the key schedule a seal or open
  leaves on the heap is erased at the next garbage collection instead of
  persisting until the memory is reused. The new `KeyScheduleErasure()`
  reports which build is running. Other builds are unchanged and keep the
  documented exposure. `make test-runtimesecret` (part of CI) proves the
  erasure against a control that must see the unerased schedule.

### Changed — BREAKING

- **An unwiped release no longer matches `ErrLockedMemoryUnavailable`** (#98).
  `ErrReleasedWithoutWipe` (the pages are gone) and
  `ErrLockedMemoryUnavailable` (the pages are still held) are now disjoint
  on release, and `UnwipedReleaseError.Cause` is the raw OS error rather than
  a `*LockedMemoryError`. Code that retried `Destroy` on
  `ErrLockedMemoryUnavailable` no longer retries a release that already
  happened.
- **`ErrSealerWiped` means the hierarchy is dead** (#98). A `ModeRootKey`
  operation whose per-call key (its DEK, or a retired KEK materialized for one
  unwrap) is destroyed by a concurrent `WipeAll` now fails with
  `ErrEnclaveDestroyed`; `ErrSealerWiped` is reported only when the root or
  the current KEK is dead. A sweep overlapping initialization or rotation
  still wipes the sealer, as before.

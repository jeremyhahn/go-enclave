### Added

- **`(*Sealer).SealFrom(ctx, src)` and `NewSealedFrom(ctx, src)`** (#145). They seal from any `Handle` with `ByteAccess`, borrowing the source and never wiping it, so a `Memory` that is already open can be re-sealed without copying its bytes onto the heap.
- **`WithBackend(b)`** (#145). The sealer imports its wrapping key, KEKs and DEKs into `b` and seals through `b`'s `AEAD` when its handles have one. It refuses a nil backend with `ErrInvalidBackend` and a backend that is not an `Importer` with a `*CapabilityError`.
- **`WithRequireKeyScheduleErasure()`, `ErrKeyScheduleExposed` and `*KeyScheduleExposedError`** (#145). With this option, `NewSealer` refuses any configuration that leaves an AES key schedule on the heap, and the error's `Name` is `"wrapping-key"` or `"dek"`. Offloading keys to a backend does not satisfy it on its own. See [sealing](docs/sealing/user.md#choose-the-type-by-access-pattern).
- **`ErrSealSourceReadOnly`**, **`ErrInvalidSealerOption`** (#145).

### Changed — BREAKING:

- **`(*Sealed).OpenIn(ctx, b Backend) (Handle, error)`** (#145). It used to take an `*Allocator` and return a `*Memory`. Pass `DefaultBackend()` to get the behaviour of `Open`; a backend that cannot import is refused with a `*CapabilityError` before anything is decrypted. See [Upgrading](docs/README.md#upgrading).
- **Copies of a `Sealer` or a `Sealed` share state** (#145). Both now keep their state behind a pointer, so destroying a copy destroys the original. `go vet` reports copies.
- **`SetSealer` refuses a sealer that `NewSealer` did not build (`ErrSealerNotConstructed`) and a destroyed one (`ErrSealerDestroyed`)** (#145).
- **`NewSealer` returns `ErrInvalidSealerOption` for a nil option** (#145). It used to panic.
- **The default sealer destroys its own `SoftwareProvider`'s root after the first successful unseal** (#145). An injected provider is never destroyed.

### Fixed

- **`NewSealed` on a view lent by `WithBytes` of an opened `Memory` crashed with a fault while wiping read-only pages** (#145). `Seal` and `NewSealed` now refuse a read-only source with `ErrSealSourceReadOnly`.
- **In `ModeRootKey`, retired KEK generations were kept for the life of the sealer** (#145). Each generation is now counted by its live values and in-flight opens and is dropped when the count reaches zero.
- **`Seal` held the sealer's read lock across the data AEAD** (#145). The AEAD now runs outside the lock, and `Destroy` is re-checked afterwards.
- **`(*Sealer).Mode()` on a nil receiver panicked** (#145).

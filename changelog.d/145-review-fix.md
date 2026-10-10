### Added

- **`ErrCleanupFailed` and `*CleanupError`** (#145). A key or plaintext handle the sealer no longer needs and whose `Destroy` fails is kept by the sealer, and the operation fails with a `*CleanupError` carrying its own failure (`Failure`) and the refusals (`Causes`). Every `(*Sealer).Destroy` retries the kept handles. See [sealing](docs/sealing/engineering.md#error-semantics).

### Fixed

- **`OpenIn` into another backend could return a live plaintext handle after `(*Sealer).Destroy`** (#145). The sealer is now checked again after the import, and the handle is destroyed and `ErrSealerDestroyed` returned.
- **A KEK rotation under `WithBackend` dropped an outgoing KEK whose `Destroy` failed and reported success** (#145). The KEK is now kept for retry and the seal returns a `*CleanupError`.
- **A failed import whose handle refused `Destroy` lost the handle and the refusal** (#145), in `OpenIn` and in the sealer's own key imports.
- **`Seal` and `NewSealed` checked only the first and last byte of the source** (#145). A source with a read-only page in the middle passed, and the wipe then crashed the process. Every page the source spans is now checked, and such a source is refused with `ErrSealSourceReadOnly`.

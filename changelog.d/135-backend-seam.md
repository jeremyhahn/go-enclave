### Added

- **The backend seam for hardware enclaves** (#135). `Handle` and `Backend`
  are the core every backend provides. `ByteAccess`, `Freezer`, `Deriver`,
  `AEAD`, `Attester`, `Importer`, `Sweeper` and `Confiner`, and the standard
  `crypto.Signer` and `crypto.Decrypter`, are optional capabilities found by
  type assertion. A named registry (`Register`, `Lookup`, `BackendNames`,
  `DefaultBackend`) always holds locked memory under `"locked-memory"`; nothing
  registers at import. `As` reaches a backend's or handle's native interface
  without panicking. `*MemoryEnclave` is a `Handle`, `ByteAccess` and
  `Freezer`, and its new `Backend` method returns the default. New typed
  errors: `ErrBackendNotRegistered` (`*BackendNotRegisteredError`),
  `ErrBackendExists` (`*BackendExistsError`), `ErrInvalidBackend`, and
  `ErrCapabilityUnsupported` (`*CapabilityError`). Behaviour is unchanged; the
  design of the wiring still to come is in `docs/backends/architecture.md`.
  `AEAD` is the package's own capability rather than `cipher.AEAD`, so `Seal`
  and `Open` return `ErrEnclaveDestroyed`, `ErrInvalidNonce` or
  `ErrAEADAuthentication` instead of panicking. `Import` takes a purpose and
  an algorithm (`WithPurpose`, `WithAlgorithm`, resolved by `NewImportSpec`,
  `ErrInvalidImport`), and each purpose fixes the imported handle's contract.
  A backend name is a configuration label, not an instance identity.

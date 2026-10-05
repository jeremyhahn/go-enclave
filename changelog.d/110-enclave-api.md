### Changed

- **`(*MemoryEnclave).Open`, `(*MemoryEnclave).OpenString` and
  `NewMemoryEnclaveFromString` are deprecated** (#110). Their
  `// Deprecated:` notices let staticcheck (SA1019) report their callers.
  They keep working; use `WithBytes` and `NewMemoryEnclave`.

### Changed — BREAKING: `(*MemoryEnclave).EqualTo` returns `(bool, error)`, and `EqualToErr` is removed

- **`(*MemoryEnclave).EqualTo` returns `(bool, error)`, and
  `EqualToErr` is removed** (#110). A destroyed or nil enclave returns
  `ErrEnclaveDestroyed` instead of a bare `false`, so a mismatch can no longer
  be confused with a missing enclave. The comparison time does not depend on
  the contents, but it does reveal whether the lengths differ.

### Changed — BREAKING: `Destroy` returns `ErrEnclaveCorrupted` instead of panicking

- **`Destroy` returns `ErrEnclaveCorrupted` instead of panicking**
  (#110). The material is still wiped and the pages released first. Every
  corruption `Destroy` detects is also reported by the next `WipeAll` in its
  `SweepError`, so a `defer e.Destroy()` that discards the error does not lose
  it. Nothing in the package panics now.

### Changed — BREAKING: `LimitError` is renamed `BudgetInUseError`

- **`LimitError` is renamed `BudgetInUseError`** (#110), matching
  the `ErrBudgetInUse` sentinel it reports. Fields and behavior are unchanged.

### Changed — BREAKING: a nil `*Allocator` returns `ErrNilAllocator`

- **a nil `*Allocator` returns `ErrNilAllocator`** (#110) from
  `New`, `NewSized`, `SetLimit`, `ForceLimit` and `TransferTo` instead of
  panicking; `New` still wipes the data it was handed. `InUse`, `Limit` and
  `Available` report 0.

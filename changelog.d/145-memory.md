### Added

- **`*Allocator` is the locked-memory backend** (#145). It implements `Backend` (name `"locked-memory"`) and `Importer`, and `(*Memory).Backend()` returns the `*Allocator` that admitted the enclave, or `DefaultBackend()` for an unbudgeted one. An `*Allocator` is never registered: `Lookup("locked-memory")` stays the unbudgeted default.
- **`ErrAllocatorNotConstructed`** (#145) for an `Allocator` not built by `NewAllocator` or `NewAllocatorWithinRLimit`, such as the zero value, from every function that takes one.
- **`WipeAll` sweeps registered backends** (#145). After locked memory it calls `Sweep` on every registered backend other than the default that implements `Sweeper`, in name order and with the caller's `ctx` unchanged. The count adds every held count. `SweepError` gains `Backends []BackendSweepFailure`, one per failed `Sweep`, and `Unwrap() []error`, which makes each backend's own error reachable with `errors.Is` and `errors.As`.
- **`ErrNilFunc`** (#145) from `(*Memory).WithBytes` for a nil function.

### Changed — BREAKING:

- **`Memory` and `Allocator` are handles to shared state** (#145). A copy is the same enclave or budget: one `Destroy` reaches every copy, and a copied `Allocator` cannot admit past the original's budget. Both carry a `noCopy` field, so `go vet` reports a dereferenced copy. The zero `Allocator` now refuses with `ErrAllocatorNotConstructed` instead of acting as a zero budget.
- **Importing the package no longer lowers `RLIMIT_CORE`; `HardenProcess` does** (#145). Importing the package changes no process state. `HardenProcess` lowers the limit to zero, soft and hard, and reads it back on every supported GOOS but Windows, so it now does something on macOS and the BSDs too. `ProcessHardening` gains `CoreDumpsDisabled`. `CoreDumpsDisabled()` reports what the last `HardenProcess` did: `ErrCoreDumpLimitNotApplied` before it runs, nil on success, or a `*CoreDumpLimitError` (`ErrCoreDumpLimitFailed`), which `HardenProcess` also returns inside its `*ProcessHardeningError`. Call `HardenProcess` from `main` to keep the old protection. See [Upgrading](docs/README.md#upgrading).

### Fixed

- **A writable enclave no longer reports `ErrReleasedWithoutWipe`** (#145). Its data is wiped before the release `mprotect`, so when that `mprotect` is refused and the unmap succeeds, `Destroy` now returns nil. Only a frozen enclave, whose data the refusal leaves in place, still reports it. The same holds for the rollback of a failed `NewMemory`, `NewMemoryCopy` or `Allocator.New`.

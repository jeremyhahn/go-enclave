### Changed

- **The locked-memory budget and shutdown-sweep docs list every exported symbol and the data flow** (#158). `docs/locked-memory-budget/api.md` gains `LockedMemoryLimit`, `LimitSource` and its values, and each budget sentinel with its error type; `docs/shutdown-sweep/api.md` gains `BackendSweepFailure`. Both `architecture.md` files gain a data-flow section and cite the handbook ownership row. The shutdown-sweep "Return values" section is now "Error semantics". The allocator is no longer called lock-free: admission is a compare-and-swap loop and retunes take a mutex.

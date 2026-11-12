### Added

- Runnable examples on pkg.go.dev for the memory enclave (`NewMemory`, `NewMemoryCopy`, `NewMemorySized` with `WithBytes` and `Freeze`, `Destroy`), the locked-memory budget (`NewAllocator`, and `SetAllocator` compiled only), backend detection (`Detect`) and the shutdown sweep (`WipeAll`); `go test` runs them, and the memory-enclave, locked-memory-budget, backend-detection and shutdown-sweep user guides link them (#333). Nothing changes for Go callers.

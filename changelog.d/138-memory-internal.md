### Changed — BREAKING:

- **`enclave.Memory` is gone; the memory enclave's type is internal** (#138). Hold the `ByteAccess` that `NewMemory`, `NewMemoryCopy`, `NewMemorySized`, `Sealed.Open` and `Allocator.New` return, and use `As` for `Freeze`. A nil or zero enclave can no longer be declared. The constructor names and the redacted `String` and `GoString` text are unchanged. See [Upgrading](docs/README.md#upgrading).

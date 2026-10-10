### Changed — BREAKING:

- **`MemoryEnclave` is now `Memory`** (#145). The package name already says "enclave", and `enclave.Memory` is the locked-memory backend's handle. There is no deprecated alias.
- **`NewMemoryEnclave`, `NewMemoryEnclaveCopy` and `NewMemoryEnclaveSized` are now `NewMemory`, `NewMemoryCopy` and `NewMemorySized`** (#145). They follow the type.
- **`SealedEnclave` is now `Sealed`** (#145). `NewSealed` already returned it, and `enclave.SealedEnclave` repeated the package.
- **`(*SealedEnclave).OpenWith(ctx, a)` is now `(*Sealed).OpenIn(ctx, a)`** (#145). It still takes an `*Allocator` and behaves as before; the name says the argument is the destination. See [Upgrading](docs/README.md#v090-alpha-from-v08).

### Changed — BREAKING:

- **Constructors return interfaces, never a pointer to a concrete type** (#138). A failed call returns a nil interface. See [Upgrading](docs/README.md#constructors-return-interfaces).
  - `NewMemory`, `NewMemoryCopy` and `NewMemorySized` return `ByteAccess`, was `*Memory`. `Memory` stays exported; `Freeze` is reached through the `Freezer` capability with `As`.
  - `NewSealed`, `NewSealedFrom`, `(*Sealer).Seal` and `(*Sealer).SealFrom` return the `Sealed` interface, was `*Sealed`; `Sealed.Open` returns `ByteAccess`, was `*Memory`.
  - `NewAllocator`, `NewAllocatorWithinRLimit` and `ProcessAllocator` return the `Allocator` interface, was `*Allocator`; `Allocator.New` and `Allocator.NewSized` return `ByteAccess`, was `*Memory`. `SetAllocator` and `Allocator.TransferTo` take an `Allocator` and refuse one this package did not build with `ErrAllocatorNotConstructed`.
  - `NewSoftwareProvider` returns the `SoftwareProvider` interface (`KeyProtector`, `RootUnsealer`, `HealthReporter` and `Destroy`), was `*SoftwareProvider`.
- **`Sealed`, `Allocator` and `SoftwareProvider` are interfaces; their implementations are internal** (#138). A caller can no longer declare a zero value or call through a nil pointer, so `ErrProviderNotConstructed`, and `ErrAllocatorNotConstructed` for a zero `Allocator{}`, no longer reach callers. `String` and `GoString` are not interface methods; printing stays redacted.

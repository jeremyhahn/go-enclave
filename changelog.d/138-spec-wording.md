### Changed

- **The SPEC's memory-enclave and sealing rows name the memory enclave, not `Memory`** (#138). They describe the shipped API: constructors and `Sealed.Open` return a `ByteAccess`, `Freeze` is the `Freezer` capability, and `Sealer` is an interface. Nothing changes for Go callers.
- **The SPEC's `enclave-interface` row is shipped** (#138): every constructor returns an interface, and no exported concrete type is a handle to locked or sealed material or to a backend. Nothing changes for Go callers.

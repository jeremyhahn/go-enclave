### Fixed

- **The integration suite and docs follow #201's nil-allocator behaviour** (#138). A nil `Allocator` given to `Sealed.OpenIn` is a nil `Backend` and returns `ErrInvalidBackend`; the integration test expected `ErrNilAllocator`, which only `SetAllocator(nil)` returns to a caller. [Upgrading](docs/README.md#constructors-return-interfaces) now says so.

### Changed — BREAKING:

- **`SoftwareProvider.Protect` no longer wraps under the root `UnsealRoot` exports** (#145). It wraps under a Protect key derived from the root with HKDF-SHA256 under its own versioned info, so the two uses never share a key. Blobs `Protect` produced before this change no longer open; the provider keeps its root only in memory, so no persisted format is affected.

### Added

- **`ErrProviderNotConstructed`** (#145): every `SoftwareProvider` method but `Destroy` reports it for a provider `NewSoftwareProvider` did not build, such as the zero value.

### Fixed

- **A copy of a `SoftwareProvider` no longer splits its lock and state** (#145). The state lives behind a pointer, so a copy shares the original's root, budget and lock, and `go vet` flags the copy.

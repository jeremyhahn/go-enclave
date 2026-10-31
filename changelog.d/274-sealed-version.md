### Added

- **The `Sealed` envelope carries a version, bound into the AAD from version 2** (#274): new seals write [version 2](docs/sealing/engineering.md#envelope-version), whose AAD is the version byte followed by the wrapped data key; contract v1 is the zero version and opens unchanged. An unknown version is refused with `ErrUnknownSealedVersion`. Nothing changes for Go callers, so there are no upgrading notes.

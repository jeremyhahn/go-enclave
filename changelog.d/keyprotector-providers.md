### Added

- **keyprotector-providers**: `backends/tpm` holds every error type and `Err...` sentinel to one contract table: the message carries the package prefix on zero and populated values, `errors.Is` matches only the type's own sentinels, `errors.As` finds the type through `%w` and `errors.Join`, `Unwrap` exposes the cause, and no byte field reaches a message; a source check fails on any exported error type or sentinel without a row (#371).

### Fixed

- **keyprotector-providers**: `backends/tpm`'s `DeviceError.Error` and `CommandError.Error` no longer panic when `Err` is nil (#371).

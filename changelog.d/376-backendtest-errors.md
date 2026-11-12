### Added

- `backendtest` holds every exported error type to one contract table: `Error()` on zero and populated values, `errors.Is` against every package sentinel, `errors.As` through `%w` and `errors.Join`, and `Unwrap`. A completeness check fails when an exported error type or `Err` sentinel has no entry (#376).

### Fixed

- `backendtest.FindingsError` with no findings now returns `backendtest: no findings` from `Error()` instead of an empty string (#376). Messages with findings are unchanged.

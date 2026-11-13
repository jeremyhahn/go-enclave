### Added

- **backend-conformance**: `backendtest.CheckRefusal`, a check hardware backend modules share: on a host without their hardware, the constructor and probe must refuse with the module's typed unavailable error naming the failing step, register no backend and leave the locked-memory budget unchanged; each broken property is a `*PropertyError` (#330).
- **backend-conformance**: `backendtest.ExampleTestBackend` is a runnable example that certifies the shipped locked-memory backend with a minimal `Config`, and the backend conformance guide links it (#367).
- **backend-conformance**: `backendtest` holds every exported error type to one contract table: `Error()` on zero and populated values, `errors.Is` against every package sentinel, `errors.As` through `%w` and `errors.Join`, and `Unwrap`. A completeness check fails when an exported error type or `Err` sentinel has no entry (#376).

### Fixed

- **backend-conformance**: `backendtest.TestBackend` reports the residue property as `ErrNotMeasured` for material that is one repeated byte, such as a fresh zeroed region, instead of failing it (#367).
- **backend-conformance**: `backendtest.FindingsError` with no findings now returns `backendtest: no findings` from `Error()` instead of an empty string (#376). Messages with findings are unchanged.

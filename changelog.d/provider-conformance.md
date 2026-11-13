### Added

- **provider-conformance**: every exported `providertest` error type and `Err...` sentinel meets one contract in a single table test (a non-empty message with the package prefix, `errors.Is` matching only the type's own sentinels, `errors.As` through `%w` and `errors.Join`, `Unwrap` exposing the cause), and a completeness check fails on an exported error type or sentinel without rows (#368).

### Fixed

- **provider-conformance**: `providertest.FindingsError` with no findings renders `providertest: no findings` instead of an empty message (#368).

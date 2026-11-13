### Added

- **provider-conformance**: `providertest` has runnable examples: `ExampleTestProvider` runs the conformance suite against the software provider with the `Config` fields the provider guide uses (`New`, `Modes`, `Logf`), and `ExampleTestProvider_invalidConfig` shows an empty `Config` refused with an error matching `ErrInvalidConfig` (#341).
- **provider-conformance**: `providertest` holds every exported error type and `Err...` sentinel to one contract in a single table test: a non-empty message with the package prefix, `errors.Is` matching only the type's own sentinels, `errors.As` through `%w` and `errors.Join`, and `Unwrap` exposing the cause; a completeness check fails on an exported error type or sentinel without rows (#368).

### Fixed

- **provider-conformance**: `providertest.FindingsError` with no findings renders `providertest: no findings` instead of an empty message (#368).

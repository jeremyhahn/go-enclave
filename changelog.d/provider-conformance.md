### Added

- **provider-conformance**: `providertest` has runnable examples: `ExampleTestProvider` runs the conformance suite against the software provider with the `Config` fields the provider guide uses (`New`, `Modes`, `Logf`), and `ExampleTestProvider_invalidConfig` shows an empty `Config` refused with an error matching `ErrInvalidConfig` (#341).
- **provider-conformance**: `providertest` holds every exported error type and `Err...` sentinel to one contract in a single table test: a non-empty message with the package prefix, `errors.Is` matching only the type's own sentinels, `errors.As` through `%w` and `errors.Join`, and `Unwrap` exposing the cause; a completeness check fails on an exported error type or sentinel without rows (#368).
- **provider-conformance**: `providertest` is held to each way a provider can keep a key past `Unprotect`: a Linux test table plants a retained copy in a package-level slice, a map value, a `sync.Pool`, a buffered channel, a parked goroutine's stack, a kept `string`, anonymous private and shared mappings, an undestroyed second memory enclave, and either half of the key, and requires exactly the residue finding for each; the clean provider passes (#348).

### Fixed

- **provider-conformance**: `providertest`'s residue sweep now also searches for each half of the key, so a provider that keeps only the first or the last 16 bytes of a recovered key is reported; it looked only for the whole key before (#348).
- **provider-conformance**: `providertest.FindingsError` with no findings renders `providertest: no findings` instead of an empty message (#368).

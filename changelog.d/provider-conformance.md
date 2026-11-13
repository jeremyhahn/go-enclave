### Added

- **provider-conformance**: `providertest` has runnable examples: `ExampleTestProvider` runs the conformance suite against the software provider with the `Config` fields the provider guide uses (`New`, `Modes`, `Logf`), and `ExampleTestProvider_invalidConfig` shows an empty `Config` refused with an error matching `ErrInvalidConfig` (#341).
- **provider-conformance**: `make consumer-check` now also runs the provider-author suite, `providertest.TestProvider`, against the software provider from a scratch module outside the repository, so a published tag's `providertest` package is built and run the way a provider author's module uses it (#343); nothing changes for Go callers.

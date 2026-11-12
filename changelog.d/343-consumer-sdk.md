### Added

- `make consumer-check` now also runs the provider-author suite, `providertest.TestProvider`, against the software provider from a scratch module outside the repository, so a published tag's `providertest` package is built and run the way a provider author's module uses it (#343). Nothing changes for Go callers.

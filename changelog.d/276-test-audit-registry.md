### Changed

- The registry unit tests no longer repeat what the shutdown-sweep integration tests already cover through the public API: eight duplicated `WipeAll` tests are removed (#276). Nothing changes for Go callers.

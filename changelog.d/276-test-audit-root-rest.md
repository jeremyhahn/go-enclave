### Changed

- The root package's remaining unit tests were audited against the integration tests (#276). Nothing changes for Go callers.
  - `constanttime_test.go`: every test kept.
  - `errors_test.go`: every test kept.
  - `osmem_test.go`: `TestCoreDumpsDisabled_UnsupportedOnlyWhereThereIsNoLimit` removed; it repeated the two platform tests of `CoreDumpsDisabled`. The `sysMap`, `sysProtect` and `sysUnmap` tests are kept: they are the only tests of those error paths.
  - `osmem_unix_test.go`: removed; its one test repeated the integration test `TestMemoryEnclave_CoreDumpLimitUnchangedByImport`.
  - `osmem_windows_test.go`: every test kept; they are the only Windows tests of these paths.

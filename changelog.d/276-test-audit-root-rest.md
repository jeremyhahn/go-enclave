### Changed

- The root package's remaining unit tests were audited against the integration tests (#276). Nothing changes for Go callers.
  - `constanttime_test.go`: every test kept.
  - `errors_test.go`: every test kept.
  - `osmem_test.go`: `TestCoreDumpsDisabled_UnsupportedOnlyWhereThereIsNoLimit` removed; it repeated the two platform tests of `CoreDumpsDisabled`. The `sysMap`, `sysProtect` and `sysUnmap` tests are kept: they are the only tests of those error paths.
  - `osmem_unix_test.go`: removed; its one test repeated the integration test `TestMemoryEnclave_CoreDumpLimitUnchangedByImport`.
  - `osmem_windows_test.go`: every test kept; they are the only Windows tests of these paths.
  - `platform_test.go`: every test kept; the build-layout checks and the protection table have no upper test.
  - `singleton_test.go`: `TestProcessSingleton_InstallIsOneShotAndRefusesNil` removed; the integration test `TestSealing_ProcessSealerIsInstalledOnce` covers the nil refusal, the one-shot install and the installed value through `SetSealer`. The retry after a failed default build is kept: no upper test reaches it.
  - `secret_erase_test.go`: every test kept; it is the only test of the `runtimesecret` build.
  - `secret_noerase_test.go`: removed; the integration test `TestSealing_KeyScheduleErasureReportsThisBuild` covers `KeyScheduleErasure` in this build, and every integration seal runs through `secretDo`.

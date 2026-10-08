### Changed — one process-memory sweep; one integration suite

- **The `/proc/self/mem` residue sweep has one implementation**, the internal
  package `internal/memscan` (#129). The root package's Linux tests and
  `providertest` both call it, so the unit tests now sweep every mapping that
  can hold a runtime copy (writable, memfd, `/dev/shm`, SysV and unlinked
  mappings), not only anonymous ones. It refuses offsets that do not fit
  `ReadAt`. `memscan.AllZero` replaces the per-package copies. No exported
  identifier, error or behaviour changes.
- **The `providertest` integration suite is folded into the enclave suite**
  (#129). It was a copy of `providertest`'s unit tests; its one devcontainer
  case, `TestProvider` with `RLIMIT_MEMLOCK` at zero reporting
  `ErrNotMeasured`, now runs in an isolated child in
  `test/integration/enclave/provider_test.go`. `make integration-test-providertest`
  and its `-fips-` variant are gone; `integration-test-provider-conformance`
  runs the enclave suite. Every integration suite stays gated at
  `COVERAGE_THRESHOLD`, and the harness at the same floor by
  `coverage-providertest`.
- The integration image now carries `internal/`, which the suite and
  `providertest` import (#129).
- `test/integration/COVERAGE.md` maps each documented feature to the
  integration tests that exercise it (#129).

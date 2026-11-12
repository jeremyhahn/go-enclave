### Added

- `make fuzz` fuzzes every native Go fuzz target in the root module and in each backend module, one at a time, for `FUZZTIME` each (default `30s`); `FUZZ` and `FUZZ_PKG` select targets by name and packages by import path, and the first failure stops the run naming the package, the target and the failing input under `testdata/fuzz/`. `make check-fuzz-runner`, part of `make lint-gates`, drives it on a stub `go` (#351).

### Fixed

- The feature-map gate no longer counts `docs/plans/` as a feature directory missing from `scripts/features.map` (#351).

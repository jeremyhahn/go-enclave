### Added

- **build-and-release**: `make fuzz` fuzzes every native Go fuzz target in the root module and in each backend module for `FUZZTIME` each (default `30s`), with `FUZZ` and `FUZZ_PKG` selecting targets and packages, and stops at the first failure naming the package, the target and the failing input under `testdata/fuzz/`. `make check-fuzz-runner`, part of `make lint-gates`, drives it on a stub `go`. ([#351](https://github.com/jeremyhahn/go-enclave/issues/351))

### Fixed

- **build-and-release**: The feature-map gate no longer counts `docs/plans/` as a feature directory missing from `scripts/features.map`. ([#351](https://github.com/jeremyhahn/go-enclave/issues/351))

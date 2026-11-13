### Added

- **build-and-release**: `make check-it-runner`, part of `make lint-gates`, runs shell tests for the integration runner behind `make integration-test-<package>`, covering its usage refusals, `go test` and `covdata` failures, the coverage floor and a cover package missing from the profile.

### Fixed

- **build-and-release**: The integration runner refuses a malformed coverage floor with exit status 2 before the suite runs, and accepts only `N` or `N.N`.
- **build-and-release**: Every integration runner usage refusal exits 2 in any POSIX sh, where a missing package, floor, `GO_ENCLAVE_IT_COVERPKG` or `GO_ENCLAVE_IT_TESTFLAGS` used to exit 1 when `sh` is bash.

### Added

- `make check-it-runner`, part of `make lint-gates`: shell tests for `build/docker/devcontainer/run-integration-tests.sh`, the runner behind `make integration-test-<package>`. The runner runs from a scratch tree with a stub `go` and the real `scripts/coverage-gate.sh`; the tests cover its usage refusals, `go test` and `covdata` failures, the coverage floor, a cover package missing from the profile, `GO_ENCLAVE_IT_PROFILE_OUT` and the removal of its temporary files. No Docker or network is needed.

### Fixed

- The integration runner refuses a malformed coverage floor (`1.2.3`, `.`, `1.`, `.5`) with exit status 2 before the suite runs. It used to run the whole suite first, and only then did the coverage gate refuse the floor. Only `N` or `N.N` is accepted.
- Every integration runner usage refusal exits 2 in any POSIX sh. A missing package, floor, `GO_ENCLAVE_IT_COVERPKG` or `GO_ENCLAVE_IT_TESTFLAGS` used to exit 1 when `sh` is bash.

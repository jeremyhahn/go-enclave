### Changed

- **The Makefile is a thin contract over `scripts/`** (#129). The inline shell of `integration-test-<pkg>`, `release-alpha`, `release-verify`, `test-runtimesecret`, `lint-integration`, `cross-build`, `clean-tools` and the scanners moved into scripts that share `scripts/lib.sh`. One test-flags variable and one tool-lookup macro replace the repeated copies, `coverage-<pkg>` now enforces `COVERAGE_THRESHOLD`, and the unit and integration suites share `scripts/coverage-gate.sh`.
- **`vet`, `staticcheck` and `gosec` no longer run twice in `make ci-fast`** (#129). golangci-lint runs them once; `make vet` and `make staticcheck` are aliases for `make lint-go`. `make gosec` remains the SARIF-writing scan CI uploads, and `make security` takes gosec's rules from `lint-go`.

### Added

- **`proto`, `docker-build` and `docker-run` targets** (#129). `proto` is a documented no-op, since the library has no `.proto`; the other two build and run the devcontainer image.
- **Feature targets** (#129). `scripts/features.sh <base> <tip>` prints the `docs/<feature>/` directories a change touches, and the Makefile maps each feature to `test-<feature>` and `integration-test-<feature>`.

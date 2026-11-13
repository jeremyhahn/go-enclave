### Added

- **build-and-release**: `make check-project-scripts`, run by `make lint-gates`, drives `swtpm-fixture.sh`, `test-runtimesecret.sh`, `cross-build.sh`, `lint-integration.sh` and `release-verify.sh` on stub tools on a temporary PATH (and a scratch git tree for `release-verify.sh`), checking each script's refusals, its exact calls on success, every failure it reports, and that `swtpm-fixture.sh` leaves no swtpm process or state directory (#349).

### Fixed

- **build-and-release**: `scripts/cross-build.sh` with no target, or with no package, is now a usage error instead of passing (#349).
- **build-and-release**: `scripts/lint-integration.sh` with no package is now a usage error instead of passing (#349).

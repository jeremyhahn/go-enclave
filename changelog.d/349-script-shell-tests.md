### Added

- `make check-project-scripts`, run by `make lint-gates`: `scripts/project-scripts_test.sh` drives `swtpm-fixture.sh`, `test-runtimesecret.sh`, `cross-build.sh`, `lint-integration.sh` and `release-verify.sh` on stub tools on a temporary PATH (and a scratch git tree for `release-verify.sh`), checking each script's refusals, its exact calls on success, every failure it reports, and that `swtpm-fixture.sh` leaves no swtpm process or state directory (#349).

### Fixed

- `scripts/cross-build.sh` passed with no target and built only the current directory with no package; both are now usage errors (#349).
- `scripts/lint-integration.sh` passed with no package; that is now a usage error (#349).

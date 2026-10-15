### Added

- **`make deps-check`, the CI standard's latest-version stage** (#212). It compares every module the root `go.mod` and `build/ci/buildgates/go.mod` require, direct and indirect, with its latest release through `go list -m -u`, names each one behind with its current and latest versions, and fails on any whose `require` or `replace` line lacks a `// held: <reason>` comment (handbook `devops.md` §9). It needs the module proxy, so `make ci` and `ci-lint` stay offline and do not run it. Nothing changes for Go callers.

### Changed

- **`golang.org/x/sys` v0.49.0, was v0.48.0** (#212), its latest release, so `make deps-check` passes.

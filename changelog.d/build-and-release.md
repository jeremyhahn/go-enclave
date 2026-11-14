### Changed

- **build-and-release**: update `golang.org/x/sys` to v0.50.0 in every module that requires it.

### Added

- **build-and-release**: a build gate for `build/ci/release-tag.sh`: plain version tags such as `v1.2.3` and `v1.2.3-alpha.1` become exactly the `tag=` and `sha=` release outputs, and a branch ref, an empty or unset ref, or a tag holding shell metacharacters, spaces, slashes, quotes, backticks, `$(...)`, newlines or a leading dash is refused with nothing written and the name not echoed (#370).
- **build-and-release**: A build gate, `TestMarkdownRelativeLinksResolve`, checks that every relative link in the repository's Markdown resolves to a path in the repository, or to an issue, pull request or milestone at the depth that reaches the repository root. The backend documents' links to the Linux secretmem design now resolve.
- **build-and-release**: `make consumer-check` also runs `providertest.TestProvider` against the software provider from a scratch module outside the repository, so a published tag's `providertest` package is built and run the way a provider author's module uses it (#343).
- **build-and-release**: `make check-project-scripts`, run by `make lint-gates`, drives `swtpm-fixture.sh`, `test-runtimesecret.sh`, `cross-build.sh`, `lint-integration.sh` and `release-verify.sh` on stub tools on a temporary PATH (and a scratch git tree for `release-verify.sh`), checking each script's refusals, its exact calls on success, every failure it reports, and that `swtpm-fixture.sh` leaves no swtpm process or state directory (#349).
- **build-and-release**: `make check-it-runner`, part of `make lint-gates`, runs shell tests for the integration runner behind `make integration-test-<package>`, covering its usage refusals, `go test` and `covdata` failures, the coverage floor and a cover package missing from the profile.
- **build-and-release**: `make fuzz` fuzzes every native Go fuzz target in the root module and in each backend module for `FUZZTIME` each (default `30s`), with `FUZZ` and `FUZZ_PKG` selecting targets and packages, and stops at the first failure naming the package, the target and the failing input under `testdata/fuzz/`. `make check-fuzz-runner`, part of `make lint-gates`, drives it on a stub `go` (#351).

### Fixed

- **build-and-release**: `scripts/cross-build.sh` with no target, or with no package, is now a usage error instead of passing (#349).
- **build-and-release**: `scripts/lint-integration.sh` with no package is now a usage error instead of passing (#349).
- **build-and-release**: The integration runner refuses a malformed coverage floor with exit status 2 before the suite runs, and accepts only `N` or `N.N`.
- **build-and-release**: Every integration runner usage refusal exits 2 in any POSIX sh, where a missing package, floor, `GO_ENCLAVE_IT_COVERPKG` or `GO_ENCLAVE_IT_TESTFLAGS` used to exit 1 when `sh` is bash.
- **build-and-release**: The feature-map gate no longer counts `docs/plans/` as a feature directory missing from `scripts/features.map` (#351).

### Added

- **build-and-release**: a build gate for `build/ci/release-tag.sh`: plain version tags such as `v1.2.3` and `v1.2.3-alpha.1` become exactly the `tag=` and `sha=` release outputs, and a branch ref, an empty or unset ref, or a tag holding shell metacharacters, spaces, slashes, quotes, backticks, `$(...)`, newlines or a leading dash is refused with nothing written and the name not echoed (#370).
- **build-and-release**: A build gate, `TestMarkdownRelativeLinksResolve`, checks that every relative link in the repository's Markdown resolves to a path in the repository, or to an issue, pull request or milestone at the depth that reaches the repository root. The backend documents' links to the Linux secretmem design now resolve.
- **build-and-release**: `make consumer-check` also runs `providertest.TestProvider` against the software provider from a scratch module outside the repository, so a published tag's `providertest` package is built and run the way a provider author's module uses it (#343).
- **build-and-release**: `make check-project-scripts`, run by `make lint-gates`, drives `swtpm-fixture.sh`, `test-runtimesecret.sh`, `cross-build.sh`, `lint-integration.sh` and `release-verify.sh` on stub tools on a temporary PATH (and a scratch git tree for `release-verify.sh`), checking each script's refusals, its exact calls on success, every failure it reports, and that `swtpm-fixture.sh` leaves no swtpm process or state directory (#349).

### Fixed

- **build-and-release**: `scripts/cross-build.sh` with no target, or with no package, is now a usage error instead of passing (#349).
- **build-and-release**: `scripts/lint-integration.sh` with no package is now a usage error instead of passing (#349).

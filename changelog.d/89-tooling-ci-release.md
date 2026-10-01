### Added

- **`release.yml`: every pushed `v*` tag is verified, gated, consumed and
  published without a manual step** (#89). It checks that the tag equals
  `v$(cat VERSION)`, that `CHANGELOG.md` has exactly one non-empty section for
  it, that no `changelog.d/` fragment or `[Unreleased]` entry was left out, and
  that the tagged commit is on `main`. It then runs the full gate on the tagged
  commit, `trivy fs` and FIPS strict mode included. It builds and runs a
  throwaway consumer that `go get`s the tag in a scratch module outside the
  repository with `GOWORK=off` and a fresh module cache. Finally it publishes
  the Gitea release with the version's CHANGELOG section as its body, marked
  as a prerelease for `-alpha`. The public GitHub mirror never publishes
  automatically: the job is skipped there, and the publish script also refuses
  any github.com host, however the URL spells it (case, port, scheme,
  userinfo, trailing dot, subdomain). Every stage runs through a Make target
  (`release-verify`, the gate targets, `consumer-check`, `release-publish`),
  so each reproduces from a shell. The workflow itself keeps only
  orchestration: reading the tag, checking that the runner injected forge
  resolution, and refusing to publish unless every stage passed.
- **Release scripts, each driven offline by `make check-scripts`** (#89).
  `scripts/release-notes.sh` extracts one version's section.
  `scripts/release-check-tag.sh` is the tag/VERSION/CHANGELOG check, which
  `make release-alpha` now also runs before it commits.
  `scripts/release-publish.sh` creates the forge release, or brings an
  existing one up to date. It attaches nothing to a tag that names a commit
  other than the gated one, and never lets the API create a missing tag. It
  checks the token as a whole string against an allowlist, so a multi-line
  value cannot add curl directives through the configuration it is written
  into.
  `scripts/release-version-check.sh` makes `make release-alpha` refuse,
  before it writes anything, a version that is not strictly greater (SemVer
  2.0.0 precedence) than the current `VERSION` and every existing `v*` tag
  (release-versioning §3).
  Every script validates its arguments as whole values, not line by line.
  `scripts/consumer-check.sh` runs the post-tag consumer build. The tests run
  against a fake forge API and against this working tree served as a module
  from a local proxy, so an API change that breaks the consumer program fails
  in its own PR.
- **New Make targets** (#89): `ci-fast` (devops §4: the part of `ci` that needs
  no Docker, currently all of it), `tidy-check`, `bench` and `bench-<pkg>`,
  `test-<pkg>`, `coverage-<pkg>`, `coverage-report` (HTML, no threshold),
  `lint-actions` (actionlint with shellcheck), `lint-scripts`,
  `trivy-misconfig` (advisory), `trivy-sarif`, `clean-tools`,
  `release-verify`, `consumer-check` and `release-publish`. Also
  `integration-test` and `integration-test-enclave`, which run
  `test/integration/<pkg>` in the devcontainer and fail, rather than pass with
  nothing to run, until the suite and devcontainer exist (#91).

### Changed

- **Every analysis tool is pinned and runs at exactly its pin** (#89).
  golangci-lint v2.13.2, staticcheck v0.8.1 (2026.2.1), gosec v2.29.0,
  govulncheck v1.7.0, actionlint v1.7.7 and shellcheck v0.9.0 match the CI
  runner image. trivy v0.74.0 and shellcheck are installed from their release
  archives. Each is verified against archive and binary SHA-256s pinned in the
  Makefile; upstream shellcheck publishes no checksums, so its binaries were
  matched against upstream's `koalaman/shellcheck:v0.9.0` image.
  `scripts/tool.sh` resolves each tool. With `TOOL_INSTALL=1` (the default) it
  installs into `bin/tools/` in the repository rather than `GOPATH/bin`. A
  cached Go tool is keyed by version and toolchain, and is reused only when
  its build metadata names that toolchain. A cached archive tool is reused
  only when it matches its pinned binary hash. With `TOOL_INSTALL=0`, which CI
  sets on our runners, it installs nothing and fails closed unless the tool on
  `PATH` reports exactly the pinned version. No `@latest` install remains.
- **Every check in the CI, nightly and release workflows is a Make target**
  (#89). gosec's flags, the coverage floor, the FIPS environment and trivy's
  flags now exist only in the Makefile, so a local run and a CI run cannot
  disagree. Tokens are read-only by default. Two kinds of job get write
  scopes, each at job level: the two jobs that upload SARIF get
  `security-events: write`, and release.yml's Publish job gets
  `contents: write` to create the release.
- **Values from a tag, a workflow or a command line are data, never shell or
  make source** (#89). The Makefile binds `TAG`, `SHA`, `MAIN_REF`, `VERSION`,
  `TOOL_INSTALL` and `COVERAGE_THRESHOLD` once, to their raw text. Recipes read
  them only as quoted shell variables, and release.yml passes them to make only
  through the environment. Git accepts a tag named v`id`, and the `v*` trigger
  matches it. Before this, such a value ran as a command before any validator
  saw it, and `$(shell …)` in a make command-line value ran inside make
  itself. gosec no
  longer excludes the non-existent `examples/` directory, and its
  `-concurrency=4` memory bound applies locally too. `make lint` now covers
  gofmt, go vet, golangci-lint, actionlint and shellcheck (devops §4).
- **`make ci` checks tidiness instead of running `go mod tidy`** (#89), and
  runs `coverage` rather than `test`, as CI does. `COVERAGE_THRESHOLD` and
  `TESTFLAGS` can no longer be lowered or dropped by an environment variable.
  The Makefile exports `GOWORK=off` (dependency-resolution §2).
- **nightly.yml installs trivy pinned and verified** (#89). It used to run
  `curl …/install.sh from main | sh`. The third-party `trivy-action` steps are
  gone too, because the CLI now produces the SARIF itself. Misconfiguration
  scanning runs on both hosts as an advisory step. `trivy fs` now also scans
  `test/`, which it used to skip.
- **CHANGELOG.md names the versions it follows**: Keep a Changelog 1.1.0 and
  Semantic Versioning 2.0.0 (#89).

# Build and release

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-11-12
> Conflicts with this document are defects. For shipped behavior the Makefile, `scripts/` and `build/ci/` are canonical: fix this document to match them.

How a change is built and gated, and how a signed release is cut, verified and
published. This page is for maintainers. The everyday targets (test, coverage,
lint, cross-build, the devcontainer) are in
[CONTRIBUTING.md](../CONTRIBUTING.md#make-targets); this page does not repeat
them. `make help` lists every target.

The project is developed on a primary forge and published to GitHub. The
release tooling talks to the primary forge through a git remote named `dev`
and through the forge's HTTP API; GitHub receives a copy of each release.

## Design

- **The Makefile is the contract.** CI calls only `make` targets, and every
  target's logic lives in `scripts/`; a workflow holds no build logic of its
  own. What passes locally passes in CI.
- **One toolchain.** Every build and test runs in the devcontainer's
  `toolchain` image (`make docker-run CMD='make test'`), which carries Go and
  every tool pinned in `scripts/tool-pins.sh` and passes every gate offline.
- **Linux runs the tests.** The BSDs and Windows are build-only: `make
  cross-build` compiles, vets and links the test binaries of every package for
  every `CROSS_TARGETS` entry, and nothing runs there
  ([test status](memory-enclave/engineering.md#test-status)).
- **A release is a signed tag on `main`.** The version is explicit, never
  derived. The tag hands off to `release.yml`, which gates the tagged commit
  again before anything is published.

## Release flow

```text
make release-alpha|release-candidate|release VERSION=…
  └─ scripts/release.sh: refuse, assemble CHANGELOG.md, sign, atomic push of main + tag
       └─ release.yml on the tag
            1. Verify    make release-verify; resolves the tag to its commit (build/ci/release-tag.sh)
            2. Gate      ci-lint, ci-build, ci-security trivy, ci-test test-fips, ci-integration
            3. Consumer  make consumer-check
            4. Publish   make release-publish (primary forge only)
```

Every job after Verify checks out the commit Verify resolved, never the moving
tag. Publish needs every earlier job; it is skipped when the workflow runs on
github.com, where a maintainer publishes the release by hand.
The published commit is then checked with
`make release-tree-check TAG=… REF=<published ref>`: its tree must be the tag's.

## Cutting a release

### Prerequisites

- A git remote named `dev` that points at the primary forge
  (`git remote rename origin dev`).
- `AGENT_GIT`, the path of the commit-signing wrapper, set in `local.mk`
  (ignored by git and refused by the releasability gate if tracked). It has no
  default: a release fails closed without it. Only a release needs it, never
  a build or a test.
- `curl` and `jq`, to read the forge's combined commit status.
- `FORGE_API_URL` (the API root, e.g. `https://git.example.com/api/v1`),
  `FORGE_REPOSITORY` (`owner/repo`) and `FORGE_TOKEN` (a read token).

### Targets

| Target | Version form |
|---|---|
| `make release-alpha VERSION=vX.Y.Z-alpha` | pre-release |
| `make release-candidate VERSION=vX.Y.Z-rc.N` | pre-release |
| `make release VERSION=vX.Y.Z` | production |

Each target accepts only its own kind and refuses the other two. All three run
`scripts/release.sh`. An `-alpha` or `-rc.N` tag is published as a pre-release.

| Variable | Meaning |
|---|---|
| `VERSION` | The version to cut, with its `v` prefix |
| `AGENT_GIT` | The signing wrapper; every git command that talks to `dev` runs as `"$AGENT_GIT" "$REPO_NAME" …` |
| `REPO_NAME` | The literal repository name, which selects the signing identity (default `go-enclave`) |
| `FORGE_API_URL`, `FORGE_REPOSITORY`, `FORGE_TOKEN` | Where and how to read the commit status of `main` |

### What `release.sh` refuses

Before it writes anything, it refuses:

- a missing version, or one not of the target's kind;
- any branch but `main`, and a local `main` that is not `dev`'s `main` as just fetched;
- a tag that exists locally or on `dev`; an unreachable `dev` refuses too;
- a version that does not move forward (`release-version-check.sh`);
- a dirty tree;
- a combined commit status on the forge that is not green, or a forge it cannot reach.

Then it writes `VERSION` unprefixed, folds `changelog.d/` into `CHANGELOG.md`
(`changelog-assemble.sh`), and requires the result to pass
`release-check-tag.sh`: no fragment left, and a literal `## [vX.Y.Z…]`
heading. It commits and signs, tags, and pushes `main` and the tag in one
atomic push, so a rejected `main` never leaves the tag behind. Repeating a
step leaves the same bytes.

### Post-tag targets

| Target | Variables | What it does |
|---|---|---|
| `make release-verify` | `TAG`, optional `MAIN_REF` | The tag agrees with `VERSION` and `CHANGELOG.md`; with `MAIN_REF`, `HEAD` is an ancestor of it |
| `make release-tree-check` | `TAG`, `REF` | Offline, in the local clone: the tree of the published commit `REF` is byte-identical to the tree of the release tag `TAG` (SPEC release criterion 8). Refuses, naming both trees, when they differ, when either does not resolve, or when `TAG` is not a release version. Writes nothing |
| `make consumer-check` | `TAG` | In a fresh directory with a fresh module cache and `GOWORK=off`, `go get`s the module at the tag, asserts the build list selected that version, runs `go mod verify`, and builds and runs `scripts/testdata/consumer` |
| `make release-publish` | `TAG`, `SHA`, `FORGE_*` (a write token) | Confirms the tag exists on the forge and names `SHA`, then creates the release or updates it in place, and reads it back. Primary forge only: it refuses an `api.github.com` endpoint |

The release body is the tag's `CHANGELOG.md` section (`release-notes.sh`).
`release-publish` never creates a tag (the forge's create-release call would
make one from the default branch) and never deletes anything, so a re-run
converges. `consumer-check` clears `GOFLAGS` and sets no `GOPRIVATE`,
`GONOSUMDB` or `GOINSECURE`: resolution is whatever the runner configured.
On the primary forge's runners, `build/ci/forge-resolution.sh` first asserts
that the runner configured it.

### Verifying a signed release

```sh
git verify-tag vX.Y.Z-alpha
git verify-commit "vX.Y.Z-alpha^{commit}"
make release-verify TAG=vX.Y.Z-alpha MAIN_REF=dev/main
make consumer-check TAG=vX.Y.Z-alpha
```

## Gates

The repository's own checks are Go tests in `build/ci/buildgates`, a module of
its own. Each target runs `vet-buildgates` first and selects tests by prefix.

| Target | Tests | What it protects |
|---|---|---|
| `make check-releasability` | `^TestReleasability` | No tracked file names private hosts, addresses or workstation paths ([below](#releasability)) |
| `make check-changelog-assembly` | `^TestChangelogAssemble` | `changelog-assemble.sh` folds fragments into the shape `release-check-tag.sh` accepts |
| `make check-scripts` | `^TestScripts` | The release, publish, tool-resolution, feature and devcontainer scripts and the Makefile entry points, driven on scratch inputs, refuse what they must; needs `jq` |
| `make check-buildgates` | every other test | Actions pinned to commit SHAs and images to digests; least-privilege workflow permissions; checkouts that write do not persist credentials; publish waits on every gate; the CI Gate's tiers match the jobs; every source file, integration test and docs folder belongs to one feature in `scripts/features.map`; the toolchain image's Go matches `go.mod`; shipped source cites no issue numbers; the integration image is scanned before any suite runs on it |
| `make lint-gates` | the four rows above | Runs `check-buildgates`, `check-releasability`, `check-changelog-assembly` and `check-scripts`: the repository's own gates beside lint. CI runs it as the Lint Gates job; `make lint` does not list it |
| `make tidy-check` | — | `go.mod` and `go.sum` are tidy, in the root and in `build/ci/buildgates` |

### Aggregates

| Target | Runs |
|---|---|
| `make ci-lint` | `tidy-check lint lint-runtimesecret lint-integration check-buildgates check-releasability check-changelog-assembly check-scripts` |
| `make ci-build` | `build cross-build` |
| `make ci-security` | `gosec gosec-runtimesecret govulncheck govulncheck-runtimesecret modverify` |
| `make ci-test` | `coverage test-runtimesecret` |
| `make ci-integration` | Builds the integration image unless the daemon holds it, scans it, and runs every integration suite on it (needs Docker) |
| `make ci-fast` | `ci-lint ci-security trivy ci-test ci-build`: everything that needs no Docker |
| `make ci` | `ci-fast ci-integration` |

The `-runtimesecret` variants build with `GOEXPERIMENT=runtimesecret`
([key-schedule erasure](sealing/engineering.md#key-schedule-heap-exposure)).
Which integration test covers which feature: [COVERAGE.md](../test/integration/COVERAGE.md).

## CI

Every stage of `ci.yml` runs in the devcontainer's toolchain image, built from the commit under test: `make
docker-build` builds it with the integration image, and the Lint and Lint
Gates jobs build it alone with `make docker-build-toolchain`.
No job installs Go or a tool on the runner. `scripts/in-toolchain-image.sh`
copies the checkout into a toolchain container, because a bind mount would
resolve on the daemon's host. The image, Lint Gates, FIPS, integration and
soak jobs run `scripts/reap-stale-ci-stacks.sh` first, which removes what a
dead runner left behind. Those jobs and the Lint job mask the forge
credentials before any other step. No step prints an env file or the job environment. The stages
keep the Go build, golangci-lint and module caches in named volumes on the
runner's Docker host, `go-enclave-ci-cache-<pr|main>-{gobuild,golangci,gomod}`,
and only a push to `main` writes the `main` set. After the image build,
`scripts/trim-ci-caches.sh` removes the largest unused volume while this
repository's volumes on that host exceed `CI_CACHE_MAX_GIB` (32).

| Job | Tier | Runs |
|---|---|---|
| Preflight | PR | One job on `ubuntu-latest` and the first of every run: the schedule guard (it refuses a `workflow_dispatch` off `main` and a pull request from a reserved checkpoint branch), the changed-files step that sets the docs-only, Lint Gates, TPM and OP-TEE path scopes, and an import-boundary check that has nothing to enforce in this repository, on the runner's shell |
| Lint | PR | One job on `ubuntu-latest`, beside the image job. It takes the toolchain image from the registry cache or builds it alone (`make docker-build-toolchain`), and each stage is a step in it: `make lint`; the `Releasability (private patterns)` search ([below](#releasability)); the static checks `make ci-lint` adds beside the Lint Gates job's (`tidy-check lint-runtimesecret lint-integration`); `make gosec`, off the full tier and not on a docs-only pull request, with no network; `make deps-check`, a lint-class gate on every event, with a network for the module proxy. A failed step does not stop the later ones. `deps-check` reports, and does not fail on, a module behind a latest release published under 7 days ago without a `// held: <reason>` comment |
| Devcontainer image | PR | One job on `ubuntu-latest`. It builds the images (`make docker-build`), and each stage is a step in the toolchain image: `make build`; `make cross-build`; `make coverage`; `make test-runtimesecret`; then, on the full tier only, `make security` (gosec included) and `trivy image` on the integration image. A failed step does not stop the later ones. `security` and `trivy image` get a network for the vulnerability databases and the module proxy. The job skips on a docs-only pull request |
| Lint Gates | PR | `make lint-gates` in the toolchain image on `ubuntu-latest`, beside the Lint job, so lint's wall time is the longer of the two. No `-k`: the first failing gate ends the step. It builds the toolchain image alone, and only when the Makefile defines the target; the gates get no network. On a pull request off the full tier it runs only when a changed file matches `LINT_GATES_PATTERN`. Here the pattern is `.`, which every path matches, so it runs on every pull request. A pattern that cannot be searched skips nothing |
| FIPS | full | `make test-fips` in the toolchain image |
| Integration | full | `make ci-integration` on `ubuntu-latest`: the user-namespace, default and FIPS strict suites, on one scanned integration image |
| Soak | nightly | `make ci-integration` looped on `ubuntu-latest` for 30 minutes, each iteration its own compose project |
| TPM swtpm Conformance | full | `make integration-test-tpm` on the runner host, with `swtpm` from the runner's package manager and Go from `setup-go`. On a pull request it runs only when a file under `backends/tpm/`, `scripts/swtpm-fixture.sh` or `ci.yml` changed |
| OP-TEE | full | `make integration-test-arm-trustzone` in the OP-TEE fixture image pinned by digest in `scripts/tool-pins.sh`; it fails when the pin is empty. It runs only when an OP-TEE path changed |
| Publish CI images | push to `main` | On the primary forge only: publishes the toolchain image to the CI image registry (`CI_IMAGE_NAMESPACE`) when the registry lacks its hash. It skips on github.com |

The **PR tier** runs on every event. The **full tier** runs on every event
but a pull request (a push to `main`, the nightly schedule, `workflow_dispatch`
on `main`) and on a pull request labelled `ci:full`. The **nightly tier** runs
on the schedule (04:00 UTC) and on `workflow_dispatch` on `main`. Label a PR
`ci:full` when it changes the API or fixes the integration suite. The label
takes effect on the PR's next push or update-branch, because a label change
starts no run (`pull_request` lists only `opened`, `synchronize` and
`reopened`). A manual `workflow_dispatch` runs only on `main`: on any other
ref the schedule guard refuses the run, no job that checks out the branch
starts and CI Gate fails, so a dispatch cannot put a pull request on the full
tier. A pull request whose every changed file is markdown or under
`docs/` (a docs-only pull request) runs the Lint job without `make gosec`, and
the Lint Gates job; the Devcontainer image job skips, and CI Gate accepts that
skip. On the full tier the build and test steps always run.

A draft pull request (a `WIP:` title) runs no CI: every job but CI Gate skips,
and CI Gate fails on a draft, so no skipped gate reads as passed. Marking the
PR ready starts no run; push an empty commit when it leaves draft.

A newer run of a pull request cancels its older run. On `main` each push, and
each scheduled or dispatched run, is its own group, keyed by event and commit,
so a merge never cancels the run of an earlier `main` commit.

`make coverage` is the test stage: the race suite across the CPU matrix, failing
when any package is below `COVERAGE_THRESHOLD` (90). `make security` includes
`ci-security`'s scans. Nothing is uploaded to code scanning. The workflow passes
the make variables `MODULE_ENV_FILE`, `IT_IMAGE`, `IT_PROJECT` and
`GO_BUILD_TAGS`. `IT_IMAGE` is
`make -s it-image`, `go-enclave-ci-it:<hash>`: a hash of the build context
(the commit's tree, the checkout's diff and every untracked file `.gitignore`
does not exclude). Every job of one commit names the same image and builds it
only when the runner's daemon lacks it; each job leases it, and
`reap-stale-ci-stacks.sh` removes an old unleased one. The root module needs no
module credential. The toolchain image also downloads each nested module's
graph, which includes the root module at the tag its `go.mod` requires, so
`make docker-build` passes `GO_BUILD_PROXY`, when set, to `docker build` as the
build argument naming the Go module proxy the image build fetches through;
unset, the Dockerfile's public proxy applies. Every CI job runs on an
`ubuntu-latest` runner, which carries no `GOPROXY`: the image jobs pass the
empty value as `GO_BUILD_PROXY="${GOPROXY:-}"`, so the image build uses the
Dockerfile's default public proxy. No proxy chain has a `direct` entry.
`MODULE_ENV_FILE` serves
`integration-test` only. `GO_BUILD_TAGS` must stay empty,
because no package is gated by a tag; the Makefile refuses any other value.

The **CI Gate** is the one required check. It runs on `ubuntu-latest` with no
checkout and no action: one shell step calls an inline
`check <job> <result> <pr|code|scoped|full|nightly>` once for each job it
needs. A skipped job passes only for the reason its class names: a `full` job
when the full tier is not selected; the `nightly` job (Soak) off the schedule
and dispatch; the `code` job (Devcontainer image) on a docs-only pull request;
the `scoped` job (Lint Gates) when no changed file matches
`LINT_GATES_PATTERN`. A skipped `pr` job (Lint and Architecture Gates among
them) fails the gate, as does any other skip, failure or cancellation, a draft
pull request, and a run the schedule guard refused.

| Workflow | Trigger | Runs |
|---|---|---|
| `ci.yml` | push to `main`, pull request to `main`, nightly schedule, dispatch on `main` | The three tiers and the CI Gate; the one CI schedule |
| `release.yml` | a `v*` tag | The [release flow](#release-flow) |
| `nightly.yml` | dispatch only | Lint sweeps: `make -k lint-sweeps` in the toolchain image when the Makefile defines the target; this repository defines none, so the job prints `OK` and passes. Trivy: `trivy-misconfig`, `trivy-sarif` |

`TOOL_INSTALL=1`, the default, installs a missing pin into `bin/tools/`.
`TOOL_INSTALL=0` installs nothing and fails closed. `ci.yml` sets neither,
because its stages run in the toolchain image, where the pinned tools are on
`PATH`. actionlint alone ignores
`TOOL_INSTALL=0`: it uses a verified copy on `PATH` or builds it at its pin.

## Values are data

A tag, a SHA or a command-line value is never parsed as shell or make source.
The Makefile's `raw_bind` stores each of `EXTERNAL_VARS` (`TAG SHA MAIN_REF
VERSION TOOL_INSTALL COVERAGE_THRESHOLD`) unexpanded and exports it, as it does
for paths (`GOCMD`, `AGENT_GIT`, `REPO_NAME`, `TOOLS_DIR`, `CMD`, ...).
Recipes read only `"$$VAR"`, and the scripts validate the whole string. Only
operator flag lists (`TESTFLAGS`, `GOSEC_FLAGS`, `TRIVY_FS_FLAGS`,
`INTEGRATION_TESTFLAGS`, `CROSS_TARGETS`) are spliced into recipes. Never write
`$(TAG)` or another external variable in a recipe. Tokens never reach a command
line or a log: `curl` reads its `Authorization` header from stdin.

| Variable | Default | Meaning |
|---|---|---|
| `TOOL_INSTALL` | `1` | `0`: use a verified pinned tool on `PATH` or fail; `1`: install it into `bin/tools/` |
| `COVERAGE_THRESHOLD` | `90` | The one coverage floor, per package, for unit and integration profiles (`coverage-gate.sh`) |
| `GOCMD` | `go` | The Go command every target runs |
| `GO_ENCLAVE_IT_PROFILE_OUT` | empty | Where to write the merged integration profile (`-` prints it) |

## Releasability

`make check-releasability` refuses a tracked file that names a private host,
address or workstation path, and tracked per-machine files (`local.mk`,
anything under `.serena/` but `project.yml`). A line that must name one carries
`lab-string-ok: <reason>` on that line or the one above it; an empty reason is
not a waiver, and there is no file-level allow list. The agent
instruction files (`CLAUDE.md`, `AGENTS.md`, `.claude/`,
`.serena/project.yml`) are reported, not refused: they are stripped from the
tree at publish.

The CI `lint` job also has a `Releasability (private patterns)` step, on every
event the job runs on. It searches the tracked tree for the patterns in the
Actions secret `RELEASABILITY_PATTERNS`, which a maintainer sets in the
repository's settings. Each line of the secret is `<class><TAB><regex>`: the
class one of `coord-host`, `internal-email`, `lab-address`, `lab-host` or
`owner-path`, optionally with an `/i` suffix, and the regex a POSIX extended
regular expression, for example `lab-host<TAB>example-private-host`. Blank
lines and lines that start with `#` are skipped. The step checks every line
first: a line without a tab, an unknown class, an empty regex or a regex
`grep -E` refuses fails the step, which prints the line number only. It then
runs `git grep -I -i -E` with the regexes: a pattern matches anywhere in a
line, without regard to case, and binary files are skipped. A matched line
that carries `lab-string-ok: <reason>` is waived; an empty reason is not a
waiver.

| The run | The step |
|---|---|
| The secret is absent or empty, on a push to `main` | Fails |
| The secret is absent or empty, on any other event (a pull request from a fork gets no secret) | Prints a notice and passes without a search |
| A line is malformed (no tab, an unknown class, an empty regex or one `grep -E` refuses) | Fails and prints the line number, never the value |
| The secret holds only blank lines and `#` lines | Fails, on every event |
| A pattern matches a line without a waiver | Fails and prints `path:line` of each match, never the value |
| A pattern matches only waived lines | Passes and prints `path:line` of each waived line and their count |
| The search cannot run (`git grep` exits above 1) | Fails |
| No pattern matches | Passes and prints the pattern count |

`make check-releasability` reads the same name differently. There the
environment variable `RELEASABILITY_PATTERNS` is the path of a site pattern
file, not the patterns: one `<class><TAB><regex>` rule per line, the class one
of `lab-address`, `lab-host` or `owner-path` and the rest a Go regular
expression, with blank lines and `#` lines skipped and any other malformed line
an error. Unset or empty, only the built-in rules run. No workflow passes the
secret to `make check-releasability`, so in CI that gate runs its built-in
rules.

## Scripts

| Script | Purpose |
|---|---|
| `lib.sh` | Shared helpers (`die`, `matches`) every script sources |
| `tool-pins.sh`, `tool.sh`, `install-tools.sh`, `clean-tools.sh` | Pinned tool versions and SHA-256s; resolve, install and remove them |
| `fmt.sh`, `scan.sh` | gofmt from the module's toolchain; run a scanner and say whether it found something or was killed |
| `cross-build.sh` | The `CROSS_TARGETS` build, vet and test link |
| `coverage-gate.sh`, `test-runtimesecret.sh` | The coverage floor; the unit tests under `GOEXPERIMENT=runtimesecret` |
| `features.sh`, `features.map` | The features a change touches, for `test-<feature>` and `integration-test-<feature>` |
| `devcontainer.sh`, `integration-image.sh`, `integration-test.sh`, `userns-test.sh`, `lint-integration.sh` | The devcontainer images; the scanned integration image and suites; the user-namespace test; proof the `integration` tag selects the suite |
| `release.sh`, `release-version-check.sh`, `release-check-tag.sh`, `changelog-assemble.sh`, `release-notes.sh` | Cutting a release ([above](#what-releasesh-refuses)) |
| `release-verify.sh`, `consumer-check.sh`, `release-publish.sh` | The [post-tag targets](#post-tag-targets) |
| `deps-check.sh`, `deps-latest.sh` | `make deps-check`: fail on a module behind its latest release; `make deps-latest`: bump every direct `github.com/jeremyhahn/` dependency to its latest tag, then tidy |
| `swtpm-fixture.sh` | `make integration-test-tpm`: a throwaway `swtpm` on loopback TCP for `backends/tpm`'s swtpm-tagged tests |
| `optee-fixture.sh`, `optee-selected.sh` | `make optee-fixture-check` and `make integration-test-arm-trustzone`: the pinned trusted-firmware OP-TEE fixture; whether a change reaches it |
| `ci-image-cache.sh`, `apk-index-sum.sh`, `in-toolchain-image_test.sh` | CI only: the toolchain image's registry cache; a checksum of the Alpine package indexes the integration image's tag hashes; the tests of `in-toolchain-image.sh` (`make check-in-toolchain-image`) |
| `in-toolchain-image.sh`, `reap-stale-ci-stacks.sh`, `trim-ci-caches.sh`, `assert-build-tags.sh` | CI only, shared unchanged with other repositories that use the same CI layout: run a command in the toolchain image on a copy of the checkout; remove this repository's stale CI containers and compose stacks; bound this repository's CI cache volumes on the host; fail when a `GO_BUILD_TAGS` tag selects no file |

`build/ci/` holds what only a workflow runs: `release-tag.sh`,
`publish-release.sh`, `summary.sh`, `forge-resolution.sh` and
`toolchain-trivy.sh` (copies the pinned trivy out of the toolchain image).

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `AGENT_GIT is unset` | Set it in `local.mk`; only a release needs it |
| `no 'dev' remote` | `git remote rename origin dev` |
| `local main (…) is not dev/main` | `git pull --ff-only dev main`, then retry |
| `tag … already exists on dev` | Versions only move forward; pick the next one |
| `curl`/`jq is required` | Install it; `make check-scripts` needs `jq` too |
| `FORGE_* is unset` or refused | Set all three; the token and URL are checked for characters a token or URL does not carry |
| The unit suite fails at startup | `RLIMIT_MEMLOCK` or `/proc` is missing ([unit-test prerequisites](../CONTRIBUTING.md#unit-test-prerequisites)) |
| `devcontainer: docker is required` | The devcontainer and integration targets need Docker; `make ci-fast` does not |
| CI Gate fails on a skipped job | A PR-tier job was skipped, or a full- or nightly-tier job in a run that selected its tier |

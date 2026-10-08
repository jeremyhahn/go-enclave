# Changelog

All notable changes to go-enclave are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.8.0-alpha] - 2026-10-08

### Security

- **Auto-merge decides only from the base branch's workflow definition**
  (#106). `automerge.yml` now triggers on `pull_request_target`,
  `workflow_run` and a schedule, so a PR can no longer rewrite the workflow
  that holds the merge token. A `code-review` PR's approval must come from
  someone other than its author, and the label and reviews are read after CI
  is green, immediately before the merge call (owner ruling 2026-10-04).
- **`.gitea/CODEOWNERS`** names the owner for `.github/`, the Makefile and
  `scripts/` (#106).

- **Corrected docs that overstated dump and swap protection** (#107): in
  `ModeRootKey` the KEK's AES key schedule reaches the ordinary heap on every
  seal and open, and the per-value DEK's in every mode, unless built with
  `GOEXPERIMENT=runtimesecret`.

### Fixed

- **`scripts/release-version-check.sh` orders pre-release identifiers as
  strings** (#106). AWK coerced identifiers such as `1e10` and numerics past
  2^53 to floating point, which could accept a lower version or refuse a
  higher one.
- **`release.yml` runs `make test-runtimesecret` before publishing** (#106), so
  a regression confined to the erasing build cannot ship.

- **A zero-value `Sealer` no longer panics or blocks** (#107): `Seal` and
  `Open` return the new `ErrSealerNotConstructed` and still wipe the input.
- **The blob a `KeyProtector.Protect` returns is copied** (#107), so a
  provider that reuses its buffer no longer corrupts sealed values, and
  destroying a value no longer zeroes the provider's slice.
- **Material whose sealed length would overflow `int` is refused** (#107) with
  `ErrMaterialTooLarge` instead of panicking in AES-GCM, which on 32-bit
  platforms was reachable at about 2 GiB.

- **`RLIMIT_MEMLOCK` is reported enforced inside user namespaces** (#109).
  `CAP_IPC_LOCK` only lifts the limit in the initial user namespace, so root of
  a rootless container used to get `LimitNotEnforced` and then a late `mlock`
  `ENOMEM` instead of `ErrBudgetExceedsRLimit`. An unreadable
  `/proc/self/uid_map` now counts as enforced.
- **`madvise` failures are `*os.SyscallError`s** (#109), naming the call like
  every other system call the package makes.

- **The residue sweep sees keys kept outside anonymous memory** (#111). It now
  reads memfd, `/dev/shm`, SysV, `/dev/zero`, unlinked and every writable
  file-backed mapping; only read-only views of on-disk files are skipped.
- **The sweep no longer panics on a 32-bit target with a mapping wider than
  `math.MaxInt32`** (#111); the read length is bounded before it is converted.
- **The ended-context `UnsealRoot` check wipes its destinations** (#111) once
  the call returns, or from the abandoned call's goroutine once the provider
  returns, so root material a misbehaving provider wrote there does not linger
  on the heap.

### Added

- **`make vuln`** runs govulncheck (#106). `lint-go`, `staticcheck` and
  `govulncheck` now also analyze the `test/buildgates` module.

- **`(*Sealer).Destroy() error` and `(*SoftwareProvider).Destroy() error`**
  (#107) release a sealer's keys (wrapping key, current KEK, retained KEK
  blobs, any pending root) and the default provider `NewSealer` created,
  never an injected one. Afterwards every seal, open and `Openable` reports the
  new `ErrSealerDestroyed`, so retired sealers no longer hold locked memory
  until `RLIMIT_MEMLOCK` runs out.
- **`GoString` on `SealedEnclave` and `MemoryEnclave`** (#107): `%#v` prints
  the same redacted form as `%v` instead of the ciphertext and wrapped key.

- **Enclave pages are excluded from forked children on Linux** (#109). Every
  mapping is marked `MADV_DONTFORK`, so a `fork(2)` child has no mapping there
  and touching an enclave faults instead of reading the material. A refused
  `madvise` fails the allocation with `ErrLockedMemoryUnavailable`, like the
  core-dump exclusion; other platforms apply nothing (x/sys exposes no
  `minherit`).
- **`HardenProcess()`, opt-in process hardening for binaries** (#109). On Linux
  it sets `PR_SET_DUMPABLE` to 0 and reports what it verified in
  `ProcessHardening`. That blocks core dumps and same-uid `ptrace`, and breaks
  same-uid debuggers; elsewhere it returns `ErrProcessHardeningUnsupported`.
  The package never calls it.

- **`make toolchain-image`** (#129) prints the toolchain image's content-addressed tag, a hash of the files that build it, for running gates in it (`VERIFY_IMAGE`).

- **Root `CLAUDE.md` and `AGENTS.md`** (#129): the layout, the Make contract, the
  devcontainer, Serena and typed-error rules, and where the feature docs live.

- **`proto`, `docker-build` and `docker-run` targets** (#129). `proto` is a documented no-op, since the library has no `.proto`; the other two build and run the devcontainer image.
- **Feature targets** (#129). `scripts/features.sh <base> <tip>` prints the `docs/<feature>/` directories a change touches, and the Makefile maps each feature to `test-<feature>` and `integration-test-<feature>`.

- **`make release-candidate VERSION=vX.Y.Z-rc.N` and `make release VERSION=vX.Y.Z`** (#134). Three release targets now exist, each cutting exactly one kind from `main` and refusing the other two: `make release-alpha` (`vX.Y.Z-alpha`, as before), `make release-candidate` (`vX.Y.Z-rc.N`) and `make release` (production only; `-alpha` and `-rc.N` are refused). They run the one `scripts/release.sh`, which replaces `scripts/release-alpha.sh` and takes the kind as its argument. The version is explicit (a missing one is an error, never a guess) and checked against `^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-alpha|-rc\.[1-9][0-9]*)?$`; a tag that exists locally or on the remote, an unreachable remote, another branch and a dirty tree are refused. `release-verify`, `release-check-tag`, `release-notes` and `release-publish` (and so `release.yml`) accept `-rc.N` wherever they accept `-alpha`, and publish it as a pre-release.

### Changed — BREAKING: `WithKeyProtector(KeyProtector)` and `WithRootUnsealer(RootUnsealer)` replace `WithProvider(any)` and `WithMode`

- **`WithKeyProtector(KeyProtector)` and `WithRootUnsealer(RootUnsealer)`
  replace `WithProvider(any)` and `WithMode`** (#108). The option selects the
  mode, so a provider that cannot serve it no longer compiles; `ErrProviderMode`
  and `ErrInvalidMode` are removed. A nil or typed-nil provider, or both
  options at once, returns the new `ErrInvalidProvider`.

### Changed — BREAKING: `WithProviderHealth` is replaced by the `HealthReporter` interface

- **`WithProviderHealth` is replaced by the `HealthReporter`
  interface** (#108). A `KeyProtector` that implements `Health() error` is
  found by type assertion and believed by `SealedEnclave.Openable`;
  `SoftwareProvider` implements it.

### Changed — BREAKING: `(*SealedEnclave).Destroy` returns `error`

- **`(*SealedEnclave).Destroy` returns `error`** (#108), matching
  `MemoryEnclave.Destroy` and `Sealer.Destroy`. It is always `nil` today.

### Changed

- **`(*MemoryEnclave).Open`, `(*MemoryEnclave).OpenString` and
  `NewMemoryEnclaveFromString` are deprecated** (#110). Their
  `// Deprecated:` notices let staticcheck (SA1019) report their callers.
  They keep working; use `WithBytes` and `NewMemoryEnclave`.

- **Package documentation states contracts, not history** (#112). Godoc comments now give each identifier's behaviour, errors, concurrency and platform caveats; design rationale lives in `docs/*/engineering.md`, and links to unexported identifiers no longer render broken on pkg.go.dev.
- **The module no longer ships a repository-walking test** (#112). The root package's `doc_test.go`, which read the source tree and queried the issue tracker, is gone, so `go test all` in a consuming module no longer runs it. An offline gate in `test/buildgates` keeps issue citations out of shipped source.

- **Auto-merge lands ready PRs in batches through a merge train** (#118).
  `automerge.yml` v6 merges every ready PR that is behind main onto a new
  `merge-train/*` branch, runs CI once on that combined tree, then
  squash-merges the PRs in order and deletes the branch. A red train drops its
  newest PR and retries; a PR that conflicts is left out with a comment. While
  main still requires up-to-date branches, PRs are updated one at a time as
  before.
- **CI runs every stage at once** (#118). Security, Test and Integration no
  longer wait for Lint and Build; CI Gate still needs every job and fails
  closed on any result but success. `ci.yml` also runs on pushes to
  `merge-train/**`.

- **A merge train lands as one up-to-date PR** (#122). `automerge.yml` v7
  opens each `merge-train/*` branch as a PR into main and squash-merges that PR
  once its CI is green, so main keeps `block_on_outdated_branch` on. Its PRs
  are then closed with a comment naming the squash commit, and the issues they
  close are closed.
- **CI no longer runs on pushes to `merge-train/**`** (#122). A train is a PR,
  so it gets CI from the `pull_request` trigger like any other.

- **`ci.yml` and `release.yml` call the same make aggregates** (#129). `make ci-lint`, `ci-build`, `ci-security`, `ci-test` and `ci-integration` replace the duplicated step lists; `make ci-fast` and `make ci` compose them. Jobs run on the bare runner with `actions/setup-go` and `go-version-file: go.mod`, tools install only on github.com (`TOOL_INSTALL`), and the integration jobs keep the hardened `integration` image. Every action remains pinned by SHA.
- **The workflows' inline shell moved to `build/ci/`** (#129). The merge workflow's script is `build/ci/automerge.sh`, which keeps its scratch files in a `mktemp` directory and is shellchecked by `make lint-scripts`; the tag, forge-resolution and publish steps are scripts beside it, and one summary script serves every gate job. The merge job checks out the default branch, without credentials, to read it.
- **`test/buildgates` is now `build/ci/buildgates`** (#129), with the Makefile, gosec exclude and path references updated.
- **`make check-action-pins` is `make check-buildgates`** (#129), with help text that says what it checks. The old name remains as an alias for one release.
- **The releasability gate reports `CLAUDE.md`, `AGENTS.md` and `.claude/` as strip-at-publish** (#129) instead of refusing them. `.gitignore` no longer ignores them, except `.claude/settings.local.json`.
- **CODEOWNERS covers `build/`** (#129).

- **The devcontainer is the one toolchain for every build and test** (#129). `build/docker/devcontainer/Dockerfile` ships two stages from a shared `base` (Go, gcc/musl-dev, the `dev` user, the module and build caches at `/gomodcache` and `/gocache`): `toolchain`, which adds every pinned tool, bash, make, git, jq and the GNU userland and is usable as any non-root uid with `HOME=/tmp` and `GOPROXY=off`; and `integration`, which adds the source with today's hardening unchanged and ships none of the tools. Modules are fetched only at build time, through the `GO_BUILD_PROXY` build argument. The compose service that runs the integration suite is now `integration`, beside a new `toolchain` service.
- **Tool pins live only in `scripts/tool-pins.sh`** (#129). The Makefile includes it and the image's tools stage installs from it through `scripts/tool.sh`, which now uses a verified copy already on `PATH` (pinned version and build toolchain, or pinned SHA-256) instead of building or downloading one.
- **Every pin tracks upstream latest** (#129): golangci-lint v2.14.0, govulncheck v1.8.0, actionlint v1.7.12, trivy v0.75.0 and shellcheck v0.11.0, Go 1.27.1 on `golang:1.27.1-alpine3.24` (by digest), and checkout v7, setup-go v7 and codeql-action v4 (by commit SHA). A pin exists only so a build is reproducible, a version plus a SHA-256 or digest, and is never below the latest release.
- **`docker-build` and `docker-run` target the toolchain** (#129). `make docker-build` builds both stages and tags `go-enclave-toolchain:<content tag>` and `:latest`; `make docker-run CMD='make lint'` runs a command in the toolchain image with the checkout mounted, offline, as the invoking user.

- **Migration guidance lives once, in `docs/README.md` "Upgrading"** (#129), now
  with a v0.8.0-alpha section covering the breaking changes since v0.7. The
  "Migrating from" sections of each `user.md` and the version history of each
  `api.md` link to it instead of repeating it.
- **The README links to the platform contract and the documentation index**
  (#129) instead of copying their tables, and no longer says Android is missing
  from `cross-build`. `docs/locked-memory/engineering.md` says Linux is the only
  OS the tests run on, not the only OS in CI (CI cross-builds every target).

- **The Makefile is a thin contract over `scripts/`** (#129). The inline shell of `integration-test-<pkg>`, `release-alpha`, `release-verify`, `test-runtimesecret`, `lint-integration`, `cross-build`, `clean-tools` and the scanners moved into scripts that share `scripts/lib.sh`. One test-flags variable and one tool-lookup macro replace the repeated copies, `coverage-<pkg>` now enforces `COVERAGE_THRESHOLD`, and the unit and integration suites share `scripts/coverage-gate.sh`.
- **`vet`, `staticcheck` and `gosec` no longer run twice in `make ci-fast`** (#129). golangci-lint runs them once; `make vet` and `make staticcheck` are aliases for `make lint-go`. `make gosec` remains the SARIF-writing scan CI uploads, and `make security` takes gosec's rules from `lint-go`.

- **One naming scheme for the OS-specific files** (#129). Each concern has one
  implementation per GOOS, named `<concern>_linux.go`, `_bsd.go`, `_windows.go`
  or `_unix.go` (code the platforms share), with `_unsupported.go` as the only
  catch-all; `_other` and `_nocore` are retired. `dontdump` and `dontfork` are
  one `madvise` concern around a single helper, Linux and the BSDs share one
  `getrlimit` path, and one table translates page protections. No exported API
  changes. `TestPlatformLayer_EveryGOOSHasExactlyOneImplementation` now covers
  every concern, not only the memory primitives.

### Changed — BREAKING: `(*MemoryEnclave).EqualTo` returns `(bool, error)`, and `EqualToErr` is removed

- **`(*MemoryEnclave).EqualTo` returns `(bool, error)`, and
  `EqualToErr` is removed** (#110). A destroyed or nil enclave returns
  `ErrEnclaveDestroyed` instead of a bare `false`, so a mismatch can no longer
  be confused with a missing enclave. The comparison time does not depend on
  the contents, but it does reveal whether the lengths differ.

### Changed — BREAKING: `Destroy` returns `ErrEnclaveCorrupted` instead of panicking

- **`Destroy` returns `ErrEnclaveCorrupted` instead of panicking**
  (#110). The material is still wiped and the pages released first. Every
  corruption `Destroy` detects is also reported by the next `WipeAll` in its
  `SweepError`, so a `defer e.Destroy()` that discards the error does not lose
  it. Nothing in the package panics now.

### Changed — BREAKING: `LimitError` is renamed `BudgetInUseError`

- **`LimitError` is renamed `BudgetInUseError`** (#110), matching
  the `ErrBudgetInUse` sentinel it reports. Fields and behavior are unchanged.

### Changed — BREAKING: a nil `*Allocator` returns `ErrNilAllocator`

- **a nil `*Allocator` returns `ErrNilAllocator`** (#110) from
  `New`, `NewSized`, `SetLimit`, `ForceLimit` and `TransferTo` instead of
  panicking; `New` still wipes the data it was handed. `InUse`, `Limit` and
  `Available` report 0.

### Changed — BREAKING: `providertest` fails closed when its residue sweep cannot measure

- **`providertest` fails closed when its residue sweep cannot
  measure** (#111). Off Linux, without locked memory, or with a blind control,
  `TestProvider` now returns an error matching the new `ErrNotMeasured`
  (`*NotMeasuredError`) instead of logging and returning `nil`. Set
  `Config.SkipResidueSweep` with a reason to accept the gap.

### Changed — BREAKING: every `providertest` error message starts with `providertest:`

- **every `providertest` error message starts with `providertest:`**
  (#111), including `PropertyError`.

### Changed — BREAKING: the deprecated `MemoryEnclave` accessors are removed

- **`MemoryEnclave.Open`, `MemoryEnclave.OpenString` and
  `NewMemoryEnclaveFromString` are removed** (#129). Read through `WithBytes`,
  and bring string material in as `NewMemoryEnclave([]byte(s))`. `Open`'s slice
  outlived the lock, so a concurrent `Destroy` or `WipeAll` unmapped it under
  its reader; every read is now a borrow.
- The enclave and allocator core is restructured with no other behavior change
  (#129): every constructor ends in one publish step, `Allocator.New` and
  `NewSized` share one admission step and refund, and `Destroy` and `WipeAll`
  book every release, orphans included, through one step. `admission.go` and
  `process_allocator.go` become `allocator.go`, `Wipe` and the constant-time
  helpers move to `constanttime.go`, and the process allocator lives in a
  generic install-once slot (`singleton.go`).

### Changed — BREAKING: one typed-error layer; `errors.Join` composites become typed errors

- **Seal and open failures are `*SealError` and `*OpenError`** (#129), not
  `errors.Join` composites. They match `ErrSealFailed` / `ErrOpenFailed` and
  unwrap to the cause, so every `errors.Is` match on the sentinels,
  `ctx.Err()`, `context.Cause` and the provider's error still holds. A sweep
  that meets a failure reports the new `*SealerWipedError`, matching
  `ErrSealerWiped`. Code that walked `Unwrap() []error` must use
  `errors.Is`/`errors.As`. A failure together with an independent cleanup
  failure is still joined, so it matches both.
- **`LockedMemoryError.Cause` is an `error`** (#129), was `any`.
- **`ProcessHardeningError` matches the new `ErrProcessHardeningFailed`**
  (#129).
- **Cause-carrying error types share one shape** (#129):
  `LockedMemoryError`, `UnwipedReleaseError`, `LimitDiscoveryError`,
  `ProcessHardeningError` and the new sealing types are aliases of one
  generic type with a `Cause error` field, rendering as the sentinel's text,
  `": "` and the cause. Struct literals and `errors.As` targets are unchanged.
- **`BudgetError` and `BudgetInUseError` messages read `<N> bytes
  requested`** (#129), was `<N> requested`.
- **`providertest.AbortedError` renders as `ErrAborted`'s text followed by the
  context's error** (#129); its `Err` field and matches are unchanged.
- Every root sentinel and error type is declared in `errors.go`, and every
  `providertest` one in `providertest/errors.go` (#129).

### Changed — one process singleton, no transitional helpers

- **`SetSealer` and the process sealer use the same install-once singleton as
  the process allocator** (#129), replacing the sealer's hand-written mutex,
  instance and lazy default. Behaviour is unchanged: `SetSealer` is still
  one-shot, and a lazily built default still counts as installed.
- The transitional helpers `destroyTransient`, `allocSized` and the lowercase
  `wipe` are gone; their call sites use `Destroy`, `NewSized` and `Wipe`
  directly. An allocation now rounds its size to whole pages once, where the
  allocator did it twice. No exported identifier, error or behaviour changes.

### Changed — one process-memory sweep; one integration suite

- **The `/proc/self/mem` residue sweep has one implementation**, the internal
  package `internal/memscan` (#129). The root package's Linux tests and
  `providertest` both call it, so the unit tests now sweep every mapping that
  can hold a runtime copy (writable, memfd, `/dev/shm`, SysV and unlinked
  mappings), not only anonymous ones. It refuses offsets that do not fit
  `ReadAt`. `memscan.AllZero` replaces the per-package copies. No exported
  identifier, error or behaviour changes.
- **The `providertest` integration suite is folded into the enclave suite**
  (#129). It was a copy of `providertest`'s unit tests; its one devcontainer
  case, `TestProvider` with `RLIMIT_MEMLOCK` at zero reporting
  `ErrNotMeasured`, now runs in an isolated child in
  `test/integration/enclave/provider_test.go`. `make integration-test-providertest`
  and its `-fips-` variant are gone; `integration-test-provider-conformance`
  runs the enclave suite. Every integration suite stays gated at
  `COVERAGE_THRESHOLD`, and the harness at the same floor by
  `coverage-providertest`.
- The integration image now carries `internal/`, which the suite and
  `providertest` import (#129).
- `test/integration/COVERAGE.md` maps each documented feature to the
  integration tests that exercise it (#129).

### Changed — sealing code split by concern

- **The sealing implementation is split into cohesive files** (#129):
  `sealer.go` keeps the `Sealer` type and its direct API; the `ModeRootKey`
  hierarchy moves to `hierarchy.go`, blob framing and the one key wrap shared
  by the hierarchy and `SoftwareProvider` to `keywrap.go`, and the AEAD
  primitives to `aead.go`; `sealed.go` keeps only `SealedEnclave`. Tests
  follow the same file names. No exported identifier, error or behaviour
  changes.
- Each hierarchy state check, key wrap, key-set destroy and
  destroy-on-failure step now has one implementation, and the provider error
  shaping is one table-driven `providerFailure` (#129).

## [v0.7.0-alpha] - 2026-10-02

### Fixed

- **KEK rotation no longer re-keys a sealer after an overlapping `WipeAll`**
  (#102). A sweep that overlaps rotation now destroys the new KEK, the old KEK
  and the root, and rotation returns `ErrSealerWiped`, as initialization
  already did.
- **A release refused while discarding a key is reported, never suppressed**
  (#102), in rotation cleanup and when a KEK whose mint failed is discarded.
  Key bytes are wiped before any unmap, so a refusal leaves locked pages, never
  key material.
- **go-enclave builds on DragonFly** (#86), and is now built and vetted there
  by `make cross-build`.
- **No mutex of a `Sealer`'s is held across a provider call** (#87). A
  provider stalled in the first `ModeRootKey` `UnsealRoot` no longer stalls
  every `Seal`, `Open` and `Openable` on that sealer, and a caller waiting for
  initialization leaves when its own context ends.
- **A shutdown sweep that overlaps the first root unseal leaves the sealer
  wiped** (#87). The root (and any minted KEK) is destroyed and the sealer
  reports `ErrSealerWiped` without asking the provider again; a refused release
  of the discarded root is reported alongside it.
- **No test copies enclave contents out of a borrow into ordinary memory**
  (security-review §6); assertions happen inside the borrow.
- **`providertest` no longer copies a provider's root onto the ordinary heap**
  (#90). The root checks compare it only inside locked enclaves, which they
  destroy afterwards.

### Changed

- **go-enclave owns its OS memory layer; `github.com/awnumar/memcall` is
  gone** (#86). Allocation, locking, protection and unmapping go directly
  through `golang.org/x/sys`, now the module's only dependency. Every #83
  release guarantee is unchanged.
- **The per-mapping core-dump exclusion now covers DragonFly** (#86):
  `MAP_NOCORE` plus a verified `MADV_NOCORE` on FreeBSD and DragonFly,
  `MAP_CONCEAL` on OpenBSD and `MADV_DONTDUMP` on Linux as before.
- **An unsupported GOOS fails to compile with one deliberate error**,
  `undefined: go_enclave_does_not_support_this_GOOS`, instead of a failure
  inside a dependency.
- **`(*SealedEnclave).Destroy` no longer waits for an `Open` in flight** (#87).
  An open already in flight completes, opens that start after `Destroy` return
  `ErrEnclaveDestroyed`, and the last open out wipes the ciphertext.
- **A borrow costs two atomic adds and one atomic load more** (#88), so a
  waiting `WipeAll` hears a borrow end. `BenchmarkBorrow*` and
  `BenchmarkIsAliveParallel` measure the cost.
- **Every analysis tool is pinned and runs at exactly its pin** (#89).
  `scripts/tool.sh` installs each tool into `bin/tools/`, verified against
  pinned SHA-256s; with `TOOL_INSTALL=0` it installs nothing and fails unless
  the tool on `PATH` reports exactly the pinned version.
- **Every check in the CI, nightly and release workflows is a Make target**
  (#89), so a local run and a CI run cannot disagree. Workflow tokens are
  read-only except for the jobs that upload SARIF or publish a release.
- **Values from a tag, a workflow or a command line are data, never shell or
  make source** (#89). `make lint` now also covers gofmt, go vet, actionlint
  and shellcheck.
- **`make ci` checks tidiness instead of running `go mod tidy`** (#89), and
  runs `coverage` as CI does. `COVERAGE_THRESHOLD` and `TESTFLAGS` can no
  longer be lowered by an environment variable.
- **nightly.yml installs trivy pinned and verified** (#89) instead of piping
  an install script from `main`. `trivy fs` now also scans `test/`.
- **CHANGELOG.md names the versions it follows**: Keep a Changelog 1.1.0 and
  Semantic Versioning 2.0.0 (#89).
- **The unit suite has no skip guards** (#90). Every former skip is now a
  failure, a guaranteed environment requirement, or a build-tagged platform
  file.
- **The suite states its locked-memory requirement**: both packages' `TestMain`
  refuse to run under a soft `RLIMIT_MEMLOCK` below 2 MiB, with one actionable
  message.
- **`make coverage` enforces the 90% floor per package**, not only on the
  total; `providertest` is now above the floor.
- **README.md and the package documentation are an overview** (#92); the
  detailed material now lives in `docs/`.
- **A `ModeRootKey` sealer wraps under a key derived from the root** (#99),
  never the provider's root itself. Sealers sharing a provider no longer share
  one random-nonce GCM key; nothing persisted changes.

### Changed — BREAKING: Windows `CoreDumpsDisabled()` reports the truth

- **`CoreDumpsDisabled()` on Windows returns `ErrCoreDumpLimitUnsupported`
  instead of `nil`** (#86), because Windows has no process-wide core-dump
  limit to lower. Code that treats a non-nil result as fatal must match the
  new sentinel to accept it deliberately. Unix semantics are unchanged.

### Changed — BREAKING: calls that reach a provider take a `context.Context`

- **Every call that can reach a provider takes a `context.Context`** (#87):
  `Protect(ctx, key)`, `Unprotect(ctx, blob, key)`, `UnsealRoot(ctx, dst)`,
  `NewSealed(ctx, data)`, `Seal(ctx, data)`, `Open(ctx)` and
  `OpenWith(ctx, a)`. An ended context fails a seal with `ErrSealFailed`, or an
  open with the new `ErrOpenFailed`, joined with the context's error. Provider
  authors: see the context contract on `RootUnsealer`.
- **A `ModePerOperation` provider's infrastructure failure on open is now
  joined under `ErrOpenFailed`** (#87); the provider's own error is still
  reachable through `errors.Is` and `errors.As`.
- **`providertest.TestProvider(ctx, cfg)`** takes a context (#87). A run whose
  context ends early returns an error matching the new
  `providertest.ErrAborted`, never `nil`.

### Changed — BREAKING: `MemoryEnclave.Destroy` returns an error

- **`MemoryEnclave.Destroy` returns an `error`, and `DestroyErr` is gone**
  (#88). It reports `ErrReleasedWithoutWipe` or `ErrLockedMemoryUnavailable`
  as `DestroyErr` did, and canary corruption still panics. Migration:
  `e.DestroyErr()` becomes `e.Destroy()`; a bare `defer e.Destroy()` still
  compiles.

### Changed — BREAKING: `WipeAll` takes a context and returns `*SweepError`

- **`WipeAll` takes a `context.Context` and waits for borrows instead of
  sleeping** (#88). `ctx` bounds every wait, and a call not admitted while
  another sweep runs returns the new `ErrSweepInProgress`. Migration:
  `WipeAll()` becomes `WipeAll(ctx)`; give a shutdown sweep a deadline.
- **The findings of an admitted `WipeAll` are a typed
  `*SweepError{Corrupt, Unwiped int}`** (#88). `errors.Is` still matches
  `ErrEnclaveCorrupted` and `ErrReleasedWithoutWipe`, and `errors.As` now
  exposes the counts.

### Changed — BREAKING: an unwiped release no longer matches `ErrLockedMemoryUnavailable`

- **An unwiped release no longer matches `ErrLockedMemoryUnavailable`** (#98).
  `ErrReleasedWithoutWipe` (the pages are gone) and
  `ErrLockedMemoryUnavailable` (the pages are still held) are now disjoint, and
  `UnwipedReleaseError.Cause` is the raw OS error. Code that retried `Destroy`
  on `ErrLockedMemoryUnavailable` no longer retries a release that already
  happened.

### Changed — BREAKING: `ErrSealerWiped` means the hierarchy is dead

- **`ErrSealerWiped` means the hierarchy is dead** (#98). A `ModeRootKey`
  operation whose per-call key is destroyed by a concurrent `WipeAll` now
  fails with `ErrEnclaveDestroyed`; `ErrSealerWiped` is reported only when the
  root or the current KEK is dead.

### Changed — BREAKING: `Open` and `OpenWith` return read-only plaintext

- **The enclave `SealedEnclave.Open` and `OpenWith` return is frozen** (#99),
  so a stray write through a retained slice faults instead of corrupting the
  plaintext. Code that wrote into an opened enclave must copy into its own
  sized enclave instead.

### Added

- **`ErrCoreDumpLimitUnsupported`** (#86), the sentinel `CoreDumpsDisabled`
  returns where there is no process-wide core-dump limit (Windows).
- **illumos, Solaris and AIX are supported** (#86), and are in
  `make cross-build` along with DragonFly and windows/386. There `mlock` needs
  a privilege, so an unprivileged process gets `ErrLockedMemoryUnavailable`
  from every allocation.
- **The conformance suite checks the provider's half of the context
  contract** (#87). `Protect`, `Unprotect` and `UnsealRoot` must refuse an
  already-canceled or expired context with that context's error, write no key
  material, and stay able to serve the next call.
- **`release.yml`: every pushed `v*` tag is verified, gated, consumed and
  published without a manual step** (#89). It checks the tag against `VERSION`
  and `CHANGELOG.md`, runs the full gate and a consumer build on the tagged
  commit, and publishes a Gitea prerelease; the GitHub mirror never publishes
  automatically.
- **Release scripts, each driven offline by `make check-scripts`** (#89):
  `release-notes.sh`, `release-check-tag.sh`, `release-publish.sh`,
  `release-version-check.sh` and `consumer-check.sh` under `scripts/`.
  `make release-alpha` now refuses a version that is not greater than
  `VERSION` and every existing `v*` tag.
- **New Make targets** (#89): `ci-fast`, `tidy-check`, `bench`, `bench-<pkg>`,
  `test-<pkg>`, `coverage-<pkg>`, `coverage-report`, `lint-actions`,
  `lint-scripts`, `trivy-misconfig`, `trivy-sarif`, `clean-tools`,
  `release-verify`, `consumer-check`, `release-publish`, `integration-test`
  and `integration-test-enclave`.
- **An integration suite that checks go-enclave's guarantees from the kernel's
  side** (#91). `test/integration/enclave/` (build tag `integration`) drives
  the public API and checks memory locking, core-dump exclusion, guard pages,
  plaintext residue, sealing and `WipeAll` against `/proc`.
- **`build/docker/devcontainer/`: the only place the suite runs.** The
  container is pinned by digest, unprivileged, read-only and offline, and the
  suite refuses to run anywhere else.
- **`make integration-test`, `make integration-test-fips`, the per-package
  `integration-test-<pkg>` / `integration-test-fips-<pkg>`, and
  `make lint-integration`.** The FIPS variant runs the suite under FIPS 140-3
  strict mode. `make ci`, a required CI `Integration` job and `release.yml`
  all run them.
- **Feature documentation under `docs/`** (#92), one folder per capability:
  `locked-memory`, `locked-memory-budget`, `sealing`, `shutdown-sweep` and
  `provider-conformance`.
- **An upgrade guide from v0.6** (#92): `docs/README.md` lists every breaking
  change since v0.6.2-alpha with before/after code.
- **`SECURITY.md`** (#92): supported versions, private reporting, scope,
  response targets and coordinated disclosure.
- **AES key schedules are erased under `runtime/secret`** (#98) in builds with
  `GOEXPERIMENT=runtimesecret` for linux/amd64 or linux/arm64 (not Android).
  The new `KeyScheduleErasure()` reports which build is running, and
  `make test-runtimesecret` (part of CI) proves the erasure.
- **`WithKEKRotationLimit(n)` sets a KEK generation's crypto-period** (#99):
  how many DEKs one generation wraps before a `ModeRootKey` sealer rotates.
  An out-of-range `n` is refused with the new `ErrInvalidRotationLimit`, and a
  seal that would need more than 2^31 generations is refused with the new
  `ErrSealerExhausted`, leaving existing values openable.

### Removed

- **The `github.com/awnumar/memcall` dependency** (#86).

## [v0.6.2-alpha] - 2026-10-01

### Fixed

- **`BudgetError.InUse` can no longer be negative** (#83). A refusal reads
  the headroom counter and then the budget without a lock, and the guard
  against an impossible pair caught only one of the two skews: a raise
  racing an over-subscribed allocator, which wraps. A lowering between the
  two reads (an idle allocator refusing a three-page request at two pages
  free, quiesced by `SetLimit(0)` in that window) paired a budget of 0 with
  two pages of headroom and reported `InUse` as -8192 on a 4 KiB-page host.
  Any negative result now takes the read-locked fallback, as a wrap already
  did. Admission is unchanged and still lock-free.
- **`make ci` builds its lint tools with this module's toolchain** (#83).
  `go install tool@version` runs outside the module, so under
  `GOTOOLCHAIN=auto` it built golangci-lint and staticcheck with the tools'
  own go1.26 floor, and both then refused this go 1.27.0 module: `make ci`
  failed at lint on a tree CI passes. Every tool install now runs under
  `GOTOOLCHAIN=$(go env GOVERSION)` resolved inside the module.
- **`make coverage` enforces the 90% floor** that previously existed only in
  `ci.yml`, so the gate reproduces locally (project-scaffold §6).
- **`make release-alpha`'s remote-tag guard fails closed.** `! git ls-remote`
  passed on every failure, including a clone with no `dev` remote; only
  exit 2 (no such ref) now counts as free, and a missing `dev` remote is named.
- **nightly.yml runs Go 1.27.0**, matching `ci.yml` and `go.mod` (it was
  1.26.7).
- **`scripts/changelog-assemble.sh` refuses to release over entries still in
  `[Unreleased]`** (#83). When `CHANGELOG.md` already had a hand-written
  section for the version and no fragment was waiting, the script took its
  no-op exit without looking at `[Unreleased]`, so `make release-alpha`
  could tag a CHANGELOG whose release section left out every entry still
  sitting there. It now fails, changing nothing, and quotes the first such
  entry. A bare `### ` heading with nothing under it is not an entry and
  does not block, matching how the fold already drops empty subsections.
- **A failed `Allocator.New` or `Allocator.NewSized` no longer refunds
  budget for pages it could not release** (#83). When construction failed
  after the pages were mapped and locked, and the rollback was refused too,
  the allocator still refunded the full charge. The budget then offered
  locked memory the process still held. The charge is now kept only while
  the pages are still mlock'd, and is returned once `WipeAll` reclaims them
  (see the failed-construction entry). A cleanup that unlocked the pages
  and was then refused the `munmap` costs address space, not locked memory,
  and is refunded at once. That is a different policy from `DestroyErr`,
  which keeps an enclave's reservation until its pages are unmapped,
  because there the enclave is the handle a retry goes through.
  The rollback of a partly built mapping also falls back to a bare `munmap`
  when `memcall.Free` is refused, as release already did, and now reports
  pages left mapped but unlocked as held. It previously reported them as
  released when both unmaps were refused after a successful `munlock`.
- **`Destroy` no longer panics when the kernel refuses a release** (#83).
  `DestroyErr` panicked on every error except `ErrReleasedWithoutWipe`. That
  included a plain refused `munlock` or `munmap` (`ENOMEM` at
  `vm.max_map_count`, for example), although the documentation says only a
  failed canary panics. Detected corruption is now the only panic. A refused
  release is returned by `DestroyErr` as `ErrLockedMemoryUnavailable`, and
  `Destroy` discards it. In both cases the enclave keeps its mapping for a
  retry, stays on the `WipeAll` ledger and keeps its `Allocator`
  reservation, as before. It reports itself destroyed once its material is
  wiped.
- **`WipeAll` reclaims the pages of a construction whose cleanup was
  refused** (#83). When a constructor failed after mapping its pages, and
  the rollback was refused too (a freeze refused by `mprotect`, then a
  release refused by `mprotect` and the bare `munmap`), it returned an error
  and dropped the only handle to pages the kernel still held. No sweep could
  reach them, even after the refusal lifted, and an `Allocator` charge kept
  for still-locked pages stayed charged for the process lifetime. Such
  mappings are now kept on an internal ledger that every `WipeAll` pass
  retries. They are included in its count while they are still mapped. The
  sweep that releases them returns any charge kept for them, exactly once.
  A mapping abandoned before any material was copied in also retries the
  bare `munmap` on every sweep when `memcall.Free` is refused, as its
  rollback did, so a bare unmap refused only transiently does not strand it.
  Likewise a refused `munlock` no longer stops its retry before the unmap,
  which takes the lock with it, so a locked orphan is reclaimed — and its
  kept charge refunded once — as soon as unmapping is possible again.
  `WipeAll`'s documentation now also states that its error reports
  `ErrReleasedWithoutWipe` alongside `ErrEnclaveCorrupted`, which it already
  did.
- **`providertest` builds on 32-bit Linux again** (#83). The residue sweep's
  signed-offset guard compared a `uintptr` against `math.MaxInt64`, which does
  not compile where `uintptr` is 32 bits, so `GOARCH=386` and `GOARCH=arm`
  could not build the package at all. The guard now widens to `uint64` first.
  `/proc/self/maps` bounds are also parsed at the width of a `uintptr` rather
  than a fixed 64 bits, so a bound that does not fit the platform is rejected
  as unparsable instead of being narrowed into a different range, and the
  header parser's table test now compiles and runs on 32-bit targets.
- **A retried release no longer unlocks pages it already unlocked** (#83).
  When a release's `munlock` succeeded and its `munmap` was refused, every
  retry through `DestroyErr` or `WipeAll` called the unlock again. Linux
  accepts that, but Windows' `VirtualUnlock` refuses pages that are not
  locked, so each retry failed at the unlock without reaching the `munmap`.
  The mapping, and any `Allocator` reservation behind it, was then held for
  the process lifetime. A mapping now records a successful unlock, a retry
  goes straight to the `munmap`, and a held release reports whether the
  pages are still locked from that same record.
- **A `ModeRootKey` sealer no longer calls `UnsealRoot` again after it
  succeeded** (#83). If minting the first KEK failed after a successful
  unseal (locked memory exhausted, for example), the root was destroyed and
  the next seal unsealed it again. That breaks the `RootUnsealer` contract
  ("at most once, retrying only if that call failed") and any one-shot root
  provider. The unsealed root is now kept and the retry re-attempts only the
  KEK mint. The kept root is an ordinary registered enclave, so `WipeAll`
  still destroys it. If a sweep does, the sealer reports `ErrSealerWiped`
  instead of unsealing a replacement.
- **A detected canary corruption is no longer lost when the release after it
  is refused** (#83). Verification wipes the guard pages and the canary.
  When the `munlock` or `munmap` after it failed, the release returned only
  that failure and kept the mapping. The retry then compared zeroes with
  zeroes and reported a clean release. The corruption flag is now sticky and
  verification runs once per mapping. An attempt that both detects
  corruption and is refused returns both, joined, so `Destroy` still panics
  with `ErrEnclaveCorrupted`, and the retry that releases the pages reports
  it again. The joined error is never counted as released: the handle,
  ledger entry and `Allocator` reservation are all kept until the pages
  actually go back.
- **`WipeAll` reports canary corruption even when the corrupt enclave's pages
  could not be released** (#83). The sweep tallied corruption only on the
  attempt that reclaimed the pages, so a corrupt enclave whose munlock or
  munmap was refused for the whole sweep was reported as still held and the
  error came back nil. Corruption is now recorded per enclave on any attempt
  that detects it, counted once however many passes retry it; such an enclave
  appears in both the count and the error.

### Added

- **`make cross-build`**, in `make ci` and the CI Build job: builds and vets
  every package for linux amd64/arm64/386/arm, darwin, freebsd, openbsd,
  netbsd and windows. DragonFly is unsupported: the pinned memcall v0.5.0 does
  not compile there.
- **`providertest` errors are typed: `ErrInvalidConfig`, `ConfigError` and
  `PropertyError`** (#83). A harness mistake and a provider defect used to be
  distinguishable only by parsing the message. A `Config` that cannot be run
  now returns a `*ConfigError` naming the field, matching `ErrInvalidConfig`
  under `errors.Is`; a provider that ran and failed returns one
  `*PropertyError` per failed property, joined, so each can be walked and
  inspected. The messages are unchanged, and the package no longer uses
  `fmt.Errorf`.

### Changed

- **FreeBSD enclaves are now verifiably excluded from core dumps with
  `MADV_NOCORE`** (#83). The per-mapping exclusion was wired only on Linux,
  and the documentation said no other platform had one; FreeBSD does.
  memcall already issued the same `madvise` inside its `Lock` but discarded
  the result. go-enclave now issues it itself and checks it, so on FreeBSD,
  as on Linux, a refused exclusion fails the allocation with
  `ErrLockedMemoryUnavailable` instead of returning an enclave whose pages
  could reach a core file. Other non-Linux platforms are unchanged.

## [v0.6.1-alpha] - 2026-09-28

### Tests

- **`TestAllocator_Refusal_NeverReportsNegativeInUse` is bounded by the
  refusals it collects, not by the retuners' iteration count** (#75). The race
  it drives ran only while the retuners ran, and the retuners stopped after a
  fixed 4000 iterations — so on a loaded host the window closed on whatever
  the refusers had managed to see in it. `make test` on a factory runner at
  load average ~26 collected 231 refusals against a floor of 500 and failed on
  the vacuity guard, on an admission path the branch had not touched.

  The guard and its threshold are unchanged; what changed is which counter
  ends the run. The retuners now carry both floors — their own iteration count
  AND the shared refusal target — and the refusers sample for as long as a
  retuner is still running. A refuser iteration was never a refusal: a raise
  to `MaxInt64` admits, and an admitted iteration counts for nothing, so a
  starved refuser used to get no more window than a scheduled one and now gets
  more. `refusersDone` is closed on every refuser exit path, the error returns
  included, so a failing refuser still releases the retuners, and the wait
  stays bounded by `waitBounded` so a real hang is a named failure rather than
  a suite timeout.

  **Which side carries the refusal target is the whole of it**, and the first
  version of this fix put it on the wrong one. Letting a refuser return as
  soon as the shared count was met reads as equivalent and is not: the
  allocator refuses from a standing start — zero budget, negative free — so
  two refusers scheduled ahead of the retuners can take the entire target off
  that static pair and be gone before the first retune lands, leaving 4000
  retunes with nobody watching. Measured with a 2ms delay forcing that order:
  18/18 green at `-cpu=1,2,8` against a build with the wrap guard REMOVED,
  every reading the unskewed `0-(-pageSize)`. Caught by codex reviewing PR
  #79; with the target on the retuners the same forced order kills the same
  broken build on 10/10 runs at `-cpu=8` and 9/10 at `-cpu=2`.

  Measured, by simulating the reported regime rather than waiting for it: a
  50µs sleep between the raise and the drop — a retuner preempted mid-cycle,
  which is what a loaded host does to it — holds the budget open so the
  refusers are admitted instead of refused. Against that, the old bound failed
  2 of 4 runs at 143 and 199 refusals, the reported shape; the new one
  collected its 500 on 6 of 6. Unforced, the defect the test exists for is
  still killed: with the wrap guard removed from `inUseFrom`, 19/20 runs at
  `-cpu=8` and 10/10 at `-cpu=2` report a negative `InUse`, at 37 to 3037
  wrapped readings each. No seam was added to the lock-free admission path.

### Added

- **Public-releasability gate: `make check-releasability`** (#80). Every
  tracked file is published — the public tree is byte-identical to the release
  tag — so the scrub has to hold in the source. The gate reads the git index
  and fails on any address in the 192.168/16 private block, a fleet hostname or private DNS
  zone, a path under the owner's home directory or the lab's NFS mount, and
  any tracked agent-only file (`CLAUDE.md`, `AGENTS.md`, `.claude/`,
  `.serena/`, `local.mk`, `task-worker.yml`). A line whose value is the point
  is waived in place with `lab-string-ok: <reason>`, the same spelling
  go-quicbaas uses. It lives in `test/buildgates` beside the action-pin gate,
  runs in `make ci` and in the Lint job, and is proven by planted values: an
  address in a tracked file fails it, the same address in an untracked file
  does not. Run against the previous `main` it reports exactly the seven
  findings removed below.
- `changelog.d/`: changes now land as fragments rather than edits to
  `CHANGELOG.md` (handbook release-versioning §5). The existing
  `[Unreleased]` section stays and releases normally.
- **`make release-alpha` assembles the fragments before tagging** (#80).
  `scripts/changelog-assemble.sh` merges `[Unreleased]` and every fragment,
  subsection by subsection, into the new version's section, deletes the
  fragments it folded in, and the release commit carries both with `VERSION`.
  It refuses, changing nothing, when a fragment is waiting behind a section
  already written by hand, when text sits outside a `###` subsection, or when
  there is nothing to release. `make check-changelog-assembly` (in `make ci`
  and the Lint job) proves every entry lands exactly once, on scratch trees
  and on a copy of this repository's own CHANGELOG.

### Changed

- **`CLAUDE.md` is no longer tracked** (#80). Agent working notes stay out of
  the published tree; the file is in `.gitignore` and the gate refuses it.
  Build, test and contribution notes for humans remain in the README.

### Fixed

- **`VERSION` reads `0.6.0-alpha`, unprefixed** (#80), as release-versioning
  §2 requires; the tag stays `v0.6.0-alpha`. `make release-alpha` wrote the
  tag string verbatim, so it now writes `$(VERSION:v%=%)`, the fix the shared
  `release-alpha.mk` template made in v2.3.
- **No lab address or fleet hostname in tracked files** (#80). The CHANGELOG's
  link references for v0.1.0-alpha through v0.3.0-alpha pointed at the retired
  internal forge by address and are removed, the #73 entry no longer quotes
  that address, and a test comment names "a factory runner" instead of the
  host a timing was measured on.

## [v0.6.0-alpha] - 2026-09-22

The release the go-truststrap go-enclave adoption wave (#7, #19, #60) builds
against: it settles the one question that held that wave, which allocator a
library admits against, in the shared library rather than in each consumer.

### Added

- **`SetAllocator` / `ProcessAllocator`: one locked-memory budget per process** (#71).
  `RLIMIT_MEMLOCK` is process-wide, so admission bounds anything only when every
  library in the process admits against the SAME allocator. Until now each
  consumer had to construct its own `Allocator`, and N of them could each stay
  inside budget while together locking past the one ceiling. go-truststrap#19
  had been blocked on that exact question ("allocator shape unruled") through
  four triage passes. go-libsignal admitted nothing at all.

  The contract is `SetSealer`'s, applied to the second process-wide resource.
  The **binary** sizes the budget once and installs it with `SetAllocator`,
  which is one-shot and fails closed with the new `ErrAllocatorInstalled`
  (`ErrNilAllocator` for nil). **Libraries** call `ProcessAllocator()` and
  allocate through it, and never install one, for the same reason they never
  call `WipeAll`. With nothing installed, the first `ProcessAllocator` call
  installs a default derived from the discovered ceiling:

  - the ceiling itself when it binds, kept sticky like `NewAllocatorWithinRLimit`;
  - a zero budget for a zero ceiling, which admits nothing because that is the
    kernel's answer;
  - unbounded where no ceiling binds (`RLIM_INFINITY`, `CAP_IPC_LOCK`, or no
    platform figure).

  The default leaves no headroom, because sizing is the binary's decision. A
  ceiling that could not be read is returned as `ErrLimitDiscoveryFailed`, and
  nothing is installed, so a later call retries. It is not defaulted around:
  an unread ceiling is not "no ceiling".

  The package-level constructors (`NewMemoryEnclave*`) are unchanged and remain
  unadmitted, so nothing moves under an existing consumer. Verified by mutation:
  dropping the one-shot check, defaulting around a failed discovery, ignoring
  `Bounded`, and dropping the install lock each fail a named test. The last one
  fails under `-race`.

### Changed

- **`golang.org/x/sys` v0.45.0 → v0.48.0** (#72), per the owner's standing rule
  to take the latest of every stack dependency. go-enclave sits under every
  Layer 0–3 library, so this pin is the floor each of them inherits. The `go`
  directive stays at the portfolio floor, `1.27.0`.
- **go-enclave is a Software Factory project** (2026-09-22). The in-repo
  review and automerge workflows (`opencode-review.yml`, `claude-review.yml`,
  `automerge.yml`) are removed. QuicBaaS reviews every pull request and posts
  `quicbaas/review`, which `main`'s protection now requires alongside
  `CI / CI Gate`. CI, nightly and release workflows are unchanged.

### Fixed

- `CLAUDE.md` no longer tells a contributor to clone the handbook from the
  retired Gitea host by its address (#73). It names the server the way the
  other factory projects do, through `git remote get-url origin`.

## [v0.5.0-alpha] - 2026-09-03

### Added

- **`providertest` — the conformance suite for the provider seam** (#64).
  go-enclave ships it; any implementer of `KeyProtector` or `RootUnsealer` — a
  TPM, an HSM, a cloud KMS — runs `providertest.TestProvider` against its own
  provider in its own repository. The shape is `fstest.TestFS`'s: one call, an
  error naming every property that failed, no import of `testing` and no
  dependency in either direction.

  **The property it enforces is RETENTION, not destination.**
  `Unprotect(blob, key []byte)` and `UnsealRoot(dst []byte)` constrain where the
  plaintext is written and say nothing about what the provider KEEPS. A provider
  may write into the caller's locked slice and hold its own copy forever, and
  from this package's side a conforming signature and a retaining implementation
  are indistinguishable. That is the unenforced half of `KeyProtector`'s
  "protects short key material outside this process", and it is the same gap
  that produced #33's fail-open: #33 made in-process retention *declarable*, and
  this makes it *detectable*.

  It does NOT assert that a provider never materializes plaintext. Measured
  against go-xkms's backends, every one returns a fresh `[]byte` from its
  decrypt — the native TPM2 path is `RSADecrypt(...) ([]byte, error)`, the
  PKCS#11 wrapper returns a slice, and the AWS, GCP, Azure and Vault backends
  return HTTP response bodies. No hardware decrypts into an arbitrary caller
  page, so demanding that would fail every real backend for conforming. What is
  required is the wipe of the transient, which the interface already states in
  words and the sweep below measures.

  Two instruments, ranked and not interchangeable. The **spy** is primary and
  deterministic: the suite is the caller, so it owns every slice the provider is
  handed, records the exact destination, asserts under a control that it held
  the material *at return time* — without which a later zero reading cannot be
  told apart from a destination that was never populated — and then requires
  that no later call disturbs it in either direction. The **residue sweep** is
  corroboration: it is the only instrument that can see a retained COPY, so it
  cannot be dropped, but a sweep that does not wipe its scan buffer replants its
  own needle and a sweep-based residue claim is unfalsifiable for anything
  transiting a stack local (both measured, #45). It wipes after every mapping,
  refuses to report a negative it has not first proven it could turn positive,
  and is skippable only with a recorded reason echoed into the log.

  Every property has a planted violator in the package's own tests that breaks
  exactly that property, and the test asserts the suite goes red and names it —
  including the headline control, a provider that retains a copy on purpose.
  A conformance suite that cannot fail is worse than none, because it certifies.

  `SoftwareProvider` passes the whole suite in both modes; that run is the
  positive control against the suite over-asserting.

  Two escape hatches, both taking a **reason** rather than a boolean, and both
  echoed into the log so a green run cannot hide what it did not measure:
  `SkipResidueSweep` for a transit the provider cannot reach (a cloud KMS
  receives its plaintext in an HTTP response body owned by `net/http`), and
  `SingleUseRoot` for a provider that consumes a one-shot handle on a
  successful unseal — the seam guarantees only that a `Sealer` calls
  `UnsealRoot` at most once, so a suite that calls it twice would fail a
  provider for honoring the contract.

### Changed

- **The test suite runs across `-cpu=1,2,8`** in CI and in `make test` /
  `make coverage` (#61). One direction of the retune-versus-admission race —
  a lowering that takes the contested page while `reserve` sits between its read
  of the headroom counter and the compare-and-swap that acts on it — is caught
  by contention rather than by arrangement, because giving it a test seam would
  put a branch on the lock-free admission path this type exists to keep clear of
  one. That makes the runner's core count part of the oracle. Measured against
  `reserve` regressed to read-then-subtract, 10 whole-package runs per setting
  on an 8-core host: `-cpu=1` killed it 0/10, `-cpu=2` 6/10, `-cpu=8` 10/10 —
  so a single-core or heavily-pinned runner cannot see the defect at all, and
  the list is what guarantees a multi-core run happens anyway. No production
  code changed. Cost: the CI test step goes from 74s to 195s, against a
  30-minute job timeout.
- `make lint` pins golangci-lint v2.13.2 — the floor for linting Go 1.27;
  v2.12.2's vendored analysis tools cannot parse the 1.27 standard library.
  CI already runs the same version baked into the runner image.
- **The `RLIMIT_MEMLOCK` check is now sticky: an allocator built by
  `NewAllocatorWithinRLimit` carries it for life.** (#46) `SetLimit` re-reads the
  ceiling and refuses to raise that allocator's budget above it with
  `ErrBudgetExceedsRLimit`, the same sentinel and the same `RLimitError` the
  constructor uses. `TransferTo` applies it to the allocator it CREDITS, since a
  transfer is a raise on the receiving side.

  Before this, the check bound a budget for exactly as long as it took to call
  `SetLimit`: #43 refused an over-ceiling budget at construction and #44 let the
  same allocator be raised straight back over it, so two entry points to one
  allocator disagreed about whether the kernel ceiling applied. It was never a
  safety hole — admission fails safe with `ErrLockedMemoryUnavailable` — but it
  lost the diagnostic the check exists for, which is failing at the setting that
  caused the problem rather than at peak load.

  **The ceiling is read fresh on every raise, never cached.** It moves: a
  setrlimit from any thread, a container resized underneath the process. A
  budget compared against a figure from startup would refuse a raise the kernel
  now permits, or permit one it now would not. The syscall is on a control-plane
  path that runs rarely, and it is taken outside the retune mutex so it cannot
  stall other retunes or the observability getters. **Nothing was added to the
  admission path**, which still reads no ceiling at all.

  Three boundaries, each with a test that fails without it:

  - **Opt-in.** A plain `NewAllocator` allocator is never checked, on any path.
    Applying the ceiling to every allocator would break callers who chose the
    unchecked constructor deliberately.
  - **Raises only.** A lowering is never refused on a ceiling, or an
    over-ceiling allocator could not move back towards compliance.
  - **`ForceLimit` overrides it**, as it overrides every other refusal on this
    type — it is the method that exists to do what `SetLimit` refuses. That is
    documented on the method rather than left implicit, so the contract is not
    mistaken for one that cannot be bypassed, and it is the escape hatch when
    discovery itself fails. The allocator stays bound afterwards: an override is
    not an opt-out.

  A discovery failure during a raise is reported as `ErrLimitDiscoveryFailed`
  and refuses the raise — nothing was compared, so nothing passed.
- **The package docs no longer present shipped API as future work** (#65).
  `doc.go` and `README.md` described `OpenWith` as "tracked as issue #17" and
  `Openable` as "tracked as issue #33" after both had shipped, and both files
  plus `provider.go` called the `crypto.Decrypter` composition an open
  decision after it was ruled will-not-ship (#50). These are package docs, so
  they reach `go doc` and pkg.go.dev: a reader was told a method they could
  call right now was a plan.

  The sentences were replaced rather than deleted, because each was doing real
  work — explaining why an obvious gap existed. `OpenWith` is now described as
  the admitted variant, keeping the reasoning about `Open` charging no budget;
  `Openable` is described by the four answers it returns, keeping the point
  that `IsAlive` cannot answer that question and must not try; and the
  `Decrypter` composition is stated as settled, on SCOPE — this package
  defines the seam and ships the software default, so a bridge adapting device
  backends belongs with the layer that owns them.

  The scope wording replaced an earlier draft that gave a MEMORY reason:
  that `crypto.Decrypter` returns a fresh slice and so "structurally cannot"
  decrypt into caller-locked memory. That claim is false, and `provider.go`
  itself refutes it thirty lines further down, where `KeyProtector`'s contract
  says in as many words that a provider whose underlying API returns a fresh
  slice must copy into the destination and wipe its transient. Every realistic
  backend is in exactly that position — the native TPM2 path is
  `RSADecrypt(...) ([]byte, error)`, PKCS#11 wrappers return a slice, and the
  cloud KMS backends return response bodies — so a fresh-slice return is the
  normal case the contract already accommodates, not a disqualifier. A public
  doc asserting a structural impossibility that the adjacent contract permits
  is worse than one that simply says where the code belongs.


### Added

- **The hardware-rootable two-mode sealing seam (#22): `SealedEnclave`,
  `Sealer`, `KeyProtector`/`RootUnsealer`, and `SoftwareProvider`.**
  Material sealed at rest as an envelope — a fresh
  per-value DEK generated into locked memory seals the material with
  AES-256-GCM (`NewGCMWithRandomNonce`, so nonce misuse is structurally
  impossible), and the DEK itself is protected by a PLUGGABLE crypto
  provider. go-enclave ships pure software only and defines the seam; TPM,
  HSM and cloud-KMS providers are injected from higher layers through
  `NewSealer(WithProvider, WithMode)` or the one-shot process default
  (`SetSealer`; `NewSealed` uses it, lazily installing the software default).

  **Providers must supply confidentiality AND authenticity** —
  `Unprotect`/`Open` fail for any blob the provider's own `Protect` did not
  produce, so a hardware-sealed value is unforgeable as well as unreadable. A
  bare RSA decryption key does not qualify (anyone holding its public key
  could forge an envelope — the finding that sank the earlier
  confidentiality-only design); a `FromDecrypterSigner` composition closing
  that gap with stdlib key interfaces was built, fully measured, and SPLIT
  OUT of this change during review — whether a `crypto.Decrypter` bridge
  ships at this layer at all is an owner decision, tracked as issue #50
  with the measurements attached. The wrapped-DEK blob is bound to the ciphertext as
  AAD, so a re-paired envelope — one value's blob against another's
  ciphertext, both halves individually authentic — fails the tag.

  **Two config-selected modes, same envelope** (`Mode` carries the honest
  comparison): `ModePerOperation` calls the device per seal/open, on the DEK
  only — the key that opens everything never enters the process, and a
  memory-reading adversary is bounded to values open during their window.
  `ModeRootKey` (the default) unseals a root once and runs an in-memory KEK
  hierarchy — the scale accommodation, stated plainly as such: after the
  unseal a live-memory adversary gets everything; what remains is the origin
  and gating of the root (device-held, PCR-bindable). KEK generations rotate
  at 2^31 wraps against the AES-GCM message bound; retired generations are
  retained as root-wrapped heap blobs — bytes, not locked pages — so rotation
  never strands a value.

  **A shutdown `WipeAll` destroys the hierarchy's keys and the sealer FAILS
  CLOSED with the distinct `ErrSealerWiped`** — never silent re-keying, which
  would make a lifecycle bug present as `ErrSealedAuthentication` and read as
  a security incident. Mode asymmetry stated on `WipeAll`: a device-held
  per-operation key survives a sweep, an in-process hierarchy does not.
  Recovery happens INTO caller-supplied memory throughout — `Open` decrypts
  straight into locked pages sized exactly (verified by process-memory
  sweeps), and the seam's recover-into signatures preserve that for providers.

  **Foreign sealed bytes remain out of contract** — no unmarshaller, pinned
  by an AST guard test whose rationale is rewritten from the obsolete
  forgery argument to the real one: there is no persistence contract, and an
  entry point would make the internal format accidentally permanent.

  `GOEXPERIMENT=boringcrypto` builds cannot seal, by decision (#34, closed):
  the only route would be `cipher.NewGCM` with caller-supplied nonces,
  weakening every build to serve a mechanism superseded by the native FIPS
  140-3 module. The refusal is documented in the package docs, on the
  constructor, and at the AEAD call site.

  Construction fails closed on a nil provider — typed or untyped — with
  `ErrProviderMode` rather than defaulting (which would silently swap a
  configured hardware provider for software) or panicking at the first seal
  (which is where a typed-nil provider detonated before review caught it).
  One test-infrastructure hardening came out of chasing a flake in the
  split-out adapter's doc-test: the shared process-memory sweep now WIPES
  its scan buffer on every return path, because an unwiped buffer let a
  later sweep find an earlier sweep's copy of the needle and report a heap
  residue that never existed in the code under test. (The second smear
  channel found — a control copy stranded on a freed, grown-away goroutine
  stack, unreachable by any wipe — is a runtime property recorded in the
  sweep's comments as a constraint on future sweep-based tests.) The
  dominating key exposure remains the `withAEAD` key-schedule copy that
  persists past GC in every mode with every provider.

  Supersedes the PR #16 single-process-key implementation per the adopted
  #22 design; its reviewed AEAD discipline, residency sweeps, key-schedule
  threat-model audit and locked-memory-exhaustion evidence carry forward
  into this envelope. New errors: `ErrSealFailed`,
  `ErrSealedAuthentication`, `ErrPlaintextEscaped`, `ErrMaterialTooLarge`,
  `ErrSealerWiped`, `ErrProviderMode`, `ErrInvalidMode`,
  `ErrSealerInstalled`, `ErrNilSealer`, `ErrProviderMessageLimit`.
- **`NewMemoryEnclaveCopy(src []byte) (*MemoryEnclave, error)` — a constructor
  that copies without consuming its source.** `NewMemoryEnclave` takes ownership
  and wipes the caller's slice on every return path; that stays the default and
  stays right. Some callers cannot honor it — a buffer owned by someone else, a
  fixture handed back on every call, material compared against the bytes it was
  built from — and they were composing `NewMemoryEnclaveSized` + `WithBytes` +
  `Destroy`-on-error by hand instead, the same eight lines in two packages of one
  consumer already. Omitting that `Destroy` leaks a locked page on a path nobody
  tests, which is the kind of mistake a constructor should make impossible rather
  than document.

  **The result is FROZEN read-only**, matching `NewMemoryEnclave` and not
  `NewMemoryEnclaveSized`. The material is complete when the constructor returns,
  so writable pages would buy nothing and would give up the protection against a
  stray write through a retained `Open` slice. The decision is in the doc comment
  because guessing it wrong is not an error — a write through frozen pages
  **faults the process** — and because the two older constructors disagree, so a
  caller generalizes from whichever it met first.

  **What the caller accepts is stated in the doc comment, not glossed:** an
  unprotected copy of the material remains on the ordinary Go heap for as long as
  the source lives. That is exactly what this package exists to avoid, and this
  constructor does not undo it — it protects the copy it holds and makes no claim
  about the source, which nothing here can wipe later because only the caller
  knows when it is done. Material that should never touch the heap at all belongs
  in `NewMemoryEnclaveSized`.

  `NewMemoryEnclave` is now implemented as this constructor plus the wipe, so the
  two cannot drift apart in the mapping, freeze or cleanup sequence — which is the
  same divergence the duplicated hand-rolled composition was heading for.
- **`(*MemoryEnclave) Freeze() error` — restore fault-on-write once a sized
  enclave's fill is done.** `NewMemoryEnclave` freezes its pages read-only as
  the material moves in, so a write through a slice retained past its borrow
  faults. `NewMemoryEnclaveSized` cannot: pages that have to be filled cannot
  arrive read-only, and until now they stayed writable for the enclave's whole
  LIFETIME. A stray write there silently corrupted the material, which is a
  strictly worse failure than a fault, and the window was the lifetime rather
  than the fill. `Freeze` closes it — after it returns, a sized enclave has
  exactly the protection a move-constructed one has.

  It is **idempotent** and **not reversible**. A second `Freeze` is a no-op, and
  so is freezing an enclave that arrived frozen, so a caller handed an enclave
  can freeze it without knowing which constructor built it. There is
  deliberately no `Melt`: a re-mutable enclave reopens the window this closes,
  and the fill is the only reason the pages were ever writable.

  It takes the **write lock**, so it waits out in-flight borrows exactly as
  `Destroy` does. That is not incidental: under the read lock the `mprotect`
  could land between two stores of a goroutine that is still filling, and a
  method whose purpose is to turn silent corruption into a fault would be
  manufacturing the fault itself. It must therefore never be called from inside
  a borrow on the same enclave, which deadlocks like any other nested call.

  A refused `mprotect` returns `ErrLockedMemoryUnavailable` (as a
  `LockedMemoryError`) and leaves the enclave **alive, writable and otherwise
  untouched** — the caller keeps what it had and knows the property was not
  established. `NewMemoryEnclave` destroys the mapping on that same failure only
  because a constructor cannot hand back a half-built enclave; here the caller
  already owns one, and destroying it underneath them would turn a failed
  hardening step into lost key material.

  The name is `Freeze`, not `Seal`. It names the mechanism, matches the internal
  `mapping.freeze` and memguard's spelling, and does not collide with the AEAD
  `Seal` that consumers of this library have in scope at exactly the call sites
  that hold key material — the same reasoning that keeps the type from being
  called a "secret".

  What it costs, stated because it is a real trade: freezing moves the
  material's wipe at `Destroy` time BEHIND a syscall that can be refused.
  `Destroy` wipes first, before anything deniable, while the region is still
  writable; a frozen region has to be made writable again first. A denied
  `mprotect` sends any enclave down #38's unwiped-release path — pages handed
  back with a bare `munmap`, `DestroyErr` reporting `ErrReleasedWithoutWipe` —
  but **a frozen enclave is the only kind whose material is still there when it
  goes**, because `wipeAndVerify` skips its early wipe exactly when the pages are
  read-only. That is measured from inside the unmap seam, in both arms, rather
  than argued. Nothing leaks either way: the pages were `mlock`'d for their whole
  life and the kernel zeroes an anonymous page before reuse. That is already true of every enclave from
  `NewMemoryEnclave` and `NewMemoryEnclaveCopy`, and an `mprotect` refused on a
  region this process already owns is a far narrower hazard than an unbounded
  window in which a retained slice rewrites a key with nothing to announce it.

  The evidence is by execution, not by assertion: a subprocess fills a sized
  enclave, freezes it, and writes through a retained slice — it must die, and
  must not have printed its survival marker. The in-process control does the
  same write on an unfrozen enclave and requires it to SUCCEED, since an
  implementation that froze sized enclaves at construction would break every
  consumer of them. (#6)
- **`NewAllocatorWithinRLimit(maxBytes int64) (*Allocator, error)` — the
  startup check for a locked-memory budget.** It discovers the process's
  `RLIMIT_MEMLOCK` and **refuses** a budget above it, returning
  `ErrBudgetExceedsRLimit` (as an `*RLimitError`) naming both the budget and the
  discovered ceiling. A service whose budget was never satisfiable learns it
  while starting, from an error that names the number to change, instead of at
  peak load from an allocation failure several layers from the setting that
  caused it.

  It fails closed rather than warning and continuing: a guard that reports a
  problem somewhere nobody correlates with the failure it later causes is the
  pattern this package exists to remove. And it is a **constructor error**, not
  an exit — a library must never `os.Exit`, `log.Fatal` or panic over a host's
  resource configuration, so the decision stays with the application.

  `NewAllocator` is unchanged and still accepts any positive budget, so nothing
  existing changes behavior.
- **`DiscoverLockedMemoryLimit() (LockedMemoryLimit, error)`**, with
  `LimitSource` and its `String`, for **deriving** a budget from the host rather
  than guessing one — and for logging where the figure came from. "8 MiB because
  `RLIMIT_MEMLOCK` said so" and "8 MiB because nothing bounded us and the config
  asked for it" are the same number and different facts.

  Three readings are handled explicitly rather than arithmetically. `RLIM_INFINITY`
  is all-bits-set, which as an `int64` is `-1` — below every budget, so treating
  it as a number would refuse them all; it reports as unlimited, and so does a
  finite limit too large to represent as the `int64` a budget is. A process
  holding **`CAP_IPC_LOCK`** may exceed the limit outright, so the figure is
  reported as `LimitNotEnforced` and refuses nothing: failing a correctly
  configured privileged service at startup, over a number the kernel will not
  apply to it, is worse than the late failure this check exists to prevent.

  The reading is a **snapshot and an upper bound on what may be assumed**, never
  a guarantee. The ceiling is process-wide and shared, a cgroup v2 `memory.max`
  frequently binds below it in a container, and it can move afterwards.
  `ErrLockedMemoryUnavailable` remains the authority on what may actually be
  locked. It is read once, at construction, and never on the allocation path.

  The ceiling is read on **Linux and on the five BSDs**, all of which define
  `RLIMIT_MEMLOCK`. `LimitUnsupported` is reported only where a platform
  genuinely exposes none — Windows bounds a working-set size instead — because
  reporting it where a ceiling *was* readable is a fail-open guard: the budget
  was checkable, the constructor said nothing, and the failure lands later under
  allocation pressure. There the constructor refuses nothing, which is the
  deliberate contract: a diagnostic that cannot run is absent, not violated, and
  refusing every budget would push callers back to the unchecked constructor and
  delete the check where it does work. `LimitUnsupported` rather than
  `LimitUnlimited` because "we did not look" is not the same claim as "the
  kernel says there is no ceiling".

  The BSD path has no CI — this repository's runners are Linux-only. Its
  classification is shared with Linux in `classifyRlimit` and tested against
  **both** platforms' `RLIM_INFINITY` sentinels, which do not agree: the BSDs
  use the largest positive `int64` and Linux all-bits-set, so reading one with
  the other's value silently yields a bounded ceiling of nine exabytes or of
  -1. Only the syscall and the sentinel constant go unexercised, and a mistake
  there fails loudly at startup rather than quietly later.
- **`ErrLimitDiscoveryFailed` and `LimitDiscoveryError`** for a ceiling that
  could not be READ, wrapping the syscall failure and reachable with
  `errors.As`. Nothing was compared, so it is deliberately neither a verdict on
  the budget nor a shortage of locked memory.

  Resolves #11 (acceptance criterion 2 of #2).
- **`(*SealedEnclave) OpenWith(a *Allocator) (*MemoryEnclave, error)` — the
  admitted open (#17).** `Open` allocates through the UNADMITTED constructors,
  so a caller bounding locked memory through an `Allocator` had no way to bound
  what opening a credential cost. That matters here because of WHEN this type
  allocates: `NewSealed` takes locked memory once, for keys, but `Open` takes a
  fresh locked page on EVERY call — a service opening a secret per connection
  allocates a locked page per connection, entirely outside the budget it
  configured. Locked memory is a process-wide ceiling, so that is the
  request-rate-driven exhaustion an `Allocator` exists to turn into a typed
  refusal.

  **One reservation per open, taken FIRST.** The destination is the only
  admitted allocation and it is the gate: an open the budget refuses has
  allocated no locked memory and has not touched a key. The transient key pages
  an open needs on the way — the per-value DEK, and for a retired KEK
  generation that generation's key — are deliberately NOT charged, so the
  process peak can exceed the budget by up to two pages per open IN FLIGHT,
  bounded because nothing transient is allocated until a reservation has been
  granted. The allocation order changed for that reason: the destination now
  precedes the DEK, where before budgets existed the DEK came first.

  Charging the transients as additional reservations was implemented first and
  rejected, and the reason is recorded on `OpenWith` because it is the kind of
  accuracy that costs availability. Two reservations per open let concurrent
  callers fragment a budget against themselves: under a budget sized for one
  open, two callers can each take a key page and then BOTH be refused for a
  destination the budget could have covered for one of them — a flood makes
  every open fail, including the legitimate ones, which is the outcome an
  `Allocator` exists to prevent. One reservation per open makes admission a
  single atomic decision, so contention refuses only the excess.

  **`OpenWith(nil)` is refused with the new `ErrNilAllocator`** rather than
  falling back to an unadmitted allocation. A caller reaches for this method to
  bound something; quietly allocating outside the budget would deliver the
  precise outcome the call was written to prevent, on a path that keeps working
  and keeps looking bounded. The unbudgeted open is still available and spelled
  differently — call `Open`, whose contract is unchanged and now says plainly
  that it allocates outside any budget.

  Not covered, and stated as a boundary rather than an omission: the SEAL path
  is still unadmitted. There is no `SealWith`; sealing allocates once per value
  rather than once per use, so it does not scale with request rate the way
  opening does.
- **`(*SealedEnclave) Openable() error` — the openability question `IsAlive`
  cannot answer (#33).** Returns nil, `ErrSealerWiped`, or
  `ErrEnclaveDestroyed`, consulting the sealer.

  It closes a NAME COLLISION. Since #40, `MemoryEnclave.IsAlive` reports false
  once its material is wiped, so across this package `IsAlive` reads as "you
  can actually use this" — while `SealedEnclave.IsAlive` tests ciphertext
  presence, which a shutdown sweep does not touch. A swept value therefore read
  alive and yielded nothing usable, which is the shape #13 was about; a doc
  comment is a weak fix for a name that means something else next door.

  `IsAlive` is deliberately UNCHANGED — its cheap, local meaning and its lock
  profile are worth keeping — and is now documented as reporting on the
  ciphertext, with `Openable` as the openability question.
- **`WithProviderHealth(fn func() error)` and `ErrOpenabilityUnknown` — an
  out-of-package provider can now report that a sweep took its sealing key
  (#33).** `SealedEnclave.Openable` consulted an UNEXPORTED interface, which by
  Go's rules no external package can satisfy, so a third-party `KeyProtector`
  keeping its key in this process's locked memory was silently assumed healthy:
  after `WipeAll` destroyed that key, `Openable` returned nil and the following
  `Open` failed. A fail-open in a health API — and it reported
  `ErrEnclaveDestroyed` rather than `ErrSealerWiped`, the same misattribution
  the decision below argues against.

  Providers that can answer now do so precisely and their answer is
  **authoritative and terminal**: the sweep-generation fallback never overrides
  it, or a provider reporting "the device still holds this key" after a sweep
  could not express the one thing the callback exists for. The callback is
  deliberately narrow — this process's sealing state, not device liveness —
  because a probe answering both would make `Openable` mean two things
  depending on which provider was installed.

  `ErrOpenabilityUnknown` **is public API**: callers match on it, so its
  identity is part of this package's compatibility surface. Added with that
  cost weighed, not as an implementation detail.

### Changed
- **An enclave whose material has been wiped now reads as DESTROYED even while
  its pages are still held.** `IsAlive` returns false, `Size` returns 0, and
  `Open`, `WithBytes`, `EqualTo` and `EqualToErr` return `ErrEnclaveDestroyed`.

  The case is the failed release: when the wipe succeeded but the `munlock` or
  `munmap` after it was refused, the mapping is deliberately **kept** so
  `Destroy` can be retried. It then read as a perfectly ordinary live enclave —
  `IsAlive` true, a non-zero `Size`, and `Open` handing back **zeroes** from a
  region whose guard pages the release path had already left **read-write**. A
  caller that recovers from `Destroy`'s panic and reads rather than
  re-destroying would derive from an all-zero secret with the guards off, and
  nothing said so.

  "The enclave still reports itself alive, which is the truth" was true of the
  **mapping** and was never true of the **enclave**. The pages stay held for the
  retry either way; only the answers about the material changed.

  **Both branches of the release path are covered.** A frozen enclave loses its
  material to the release `mprotect`; a mutable one — a sized enclave that has not
  been frozen (#6) — loses it to the *early* wipe that runs before any
  syscall that can be refused, so its material is gone even when that `mprotect`
  is the step that fails. The two differ in fact, and the flag follows the fact:
  a genuinely refused wipe still reads as alive, because nothing was destroyed.
- **`WipeAll` will not be extended to sweep `SealedEnclave` values (#33,
  decided; no behavior change).** Three grounds, now recorded where the count is
  defined rather than left open in an issue. The COUNT means "still holding
  locked memory" and that invariant is the function's whole value; a
  `SealedEnclave` holds none — its envelope is heap ciphertext — so covering it
  would either corrupt the number or require a second one. Sweeping would also
  be WRONG rather than merely costly: in `ModePerOperation` the device still
  holds the key, so a swept value stays legitimately openable, and destroying it
  would destroy recoverable application data that this process's memory never
  protected — under a call documented for sweep-and-keep-running callers. And it
  would REGRESS diagnostics, since a swept value would report
  `ErrEnclaveDestroyed` ("you destroyed this") in place of `ErrSealerWiped` ("a
  sweep did"), sending an operator to the wrong code.
- **`Openable` now answers "I cannot tell" instead of guessing, and `WipeAll`
  bumps a sweep generation before it destroys anything (#33).** For a provider
  that reports no health, `Openable` returns nil until a sweep has run and
  `ErrOpenabilityUnknown` afterwards. Gating on a sweep having actually
  happened is what keeps it a signal: an answer that read "unknown" both before
  and after would be structurally unable to report the one event it exists to
  report, and would replace a true nil with a permanent false alarm for every
  contract-abiding hardware provider.

  The ORDER inside `WipeAll` is the correctness of this, not a detail. Bump
  then destroy leaves at worst a brief false "unknown" while a sweep is in
  flight, which is the safe direction. Destroy then bump would leave a window
  where the keys are gone and the generation still reads old, so `Openable`
  returns nil about a value that can no longer be opened — the same fail-open,
  narrowed to a race that only appears under load. Pinned by a test that PARKS
  between the two steps rather than trusting statement order to survive an
  edit, with controls asserting the seam fired and the enclave was still alive
  inside the window.

  The fallback is scoped to `ModePerOperation`. In `ModeRootKey` the hierarchy
  is this package's own enclaves and it inspects them directly, so a nil there
  is knowledge rather than ignorance and a sweep elsewhere must not downgrade
  it.

### Security

- **A release whose `mprotect` is denied now hands the pages back with a bare
  `munmap` instead of keeping them, and says so.** The wipe that precedes a
  release needs the region writable; for a FROZEN enclave that mprotect is the
  only way in, so a permanent denial — a seccomp filter, a sandbox — left the
  material resident in locked memory for the process lifetime, and retrying
  could not help. The release now falls back to unmapping directly. Nothing
  leaks: the pages were `mlock`'d for their whole life and the kernel zeroes an
  anonymous page before reuse.

  It is reported rather than silent, through the new `ErrReleasedWithoutWipe`
  (as an `UnwipedReleaseError`) and the new **`(*MemoryEnclave) DestroyErr()
  error`** — `Destroy` with its non-fatal report kept rather than discarded,
  the same relationship `EqualToErr` has to `EqualTo`. It is deliberately not
  `ErrEnclaveCorrupted` and does not panic: no memory was corrupted and no
  material outlived its enclave. What it tells an operator is that something in
  the environment is denying `mprotect`, which reaches every other enclave in
  the process. (#38)
- **`Allocator.SetLimit`, `Allocator.ForceLimit` and `Allocator.TransferTo` — a
  budget that can be retuned at runtime and rebalanced between allocators.**
  (#35) Until now `Allocator.limit` was written once in `NewAllocator` and never
  again, so a process whose locked-memory demand moved — a per-tenant seal
  barrier gaining and losing tenants, a container resized under it — could not
  adjust without rebuilding its allocators.

  The two lowering contracts are separate methods because they answer different
  questions. `SetLimit` **refuses** to shrink below the memory already reserved,
  returning a `LimitError` matching the new `ErrBudgetInUse` and changing
  nothing: the reservations belong to live enclaves that only their owners may
  destroy, and no budget decision may invalidate them. `ForceLimit` records a
  ceiling that moved regardless of what is reserved, keeps every live enclave
  working, **returns the over-subscription in bytes** so the caller is told
  rather than left to discover it, and admits nothing further until reservations
  drain beneath the new budget. Zero is a legal runtime budget — quiescing an
  allocator — even though it remains a construction-time error.
- **The admission counter now holds the REMAINING budget rather than the bytes
  used**, which is what makes a moving budget safe. Every operation reduces to
  one signed adjustment of that single word: admitting subtracts, releasing
  adds, raising the budget adds, lowering it subtracts. A budget reduction and
  an allocation therefore compete on exactly the same terms, through the same
  compare-and-swap, and one of them loses — where a limit and a usage counter in
  two separate words would have let a lowering land invisibly between an
  admission's check and its commit, over-committing locked memory the process
  cannot actually get.

  Admission is unchanged in cost and remains lock-free: one atomic word, no
  syscall on refusal. The new mutex serializes budget CHANGES only, and the
  observability getters take it shared so `InUse()` is an exact figure rather
  than a torn pair. It is never taken on the allocation or release path.

  A side benefit: the admission predicate is now `charge > free`, a comparison
  with no arithmetic between the two values, so the overflow class the previous
  `charge > limit-used` form was carefully written to avoid cannot arise at all.
  The DIAGNOSTIC path still subtracts, and `BudgetError.InUse` is now documented
  and tested as never negative: an over-subscribed allocator has a negative
  headroom counter, and a lock-free reader catching it beside a freshly raised
  limit would otherwise compute a byte count that wrapped. A wrapped count is not
  a stale reading but an impossible one, and a consumer graphing it cannot tell
  the difference. Caught by Codex on PR #44.

  `Available()` reports zero rather than a negative remainder while an allocator
  is over-subscribed, and `BudgetError.InUse` may now exceed `BudgetError.Limit`
  — both states are reachable only through `ForceLimit`, and both are what an
  over-subscribed allocator honestly looks like.
- **`Allocator.TransferTo` moves headroom between two allocators as one
  operation.** Doing it as a lowering plus a raise leaves a window in which the
  bytes are in both allocators or in neither, depending on the order; "both"
  lets each side admit against the same locked memory. The transfer debits the
  source first and credits the destination second, so the intermediate state is
  always "in neither" — conservative, recoverable by a retry, and unobservable
  to any other retune since both locks are held across it. The two locks are
  taken in a fixed total order (ascending construction id), which is what makes
  concurrent A→B and B→A transfers impossible to deadlock.

  No parent/child budget hierarchy was introduced; #35 records that as an
  architecture decision for the owner, and direct transfer does not need one.

  None of the three re-checks `RLIMIT_MEMLOCK`, exactly as `NewAllocator` does
  not. An allocator built by `NewAllocatorWithinRLimit` (#43) can be raised back
  above the ceiling that constructor refused, so that check is a startup check
  and does not carry forward; `SetLimit`'s doc comment says so. Applying it to a
  retune would be a behavior decision for the owner rather than a gap to fill
  quietly, and admission fails safe regardless — the kernel refuses the lock and
  the allocation returns `ErrLockedMemoryUnavailable`.

### Tests

- **A stale forward reference in the docs now fails the suite (#65).**
  `docs_issue_refs_test.go` classifies every issue citation in the documented
  surface — the non-test `*.go` comments, `README.md` and `CLAUDE.md` — as
  `classHistorical` (describes something already done or decided),
  `classPending` (presents the issue as unresolved future work) or
  `classExternal` (another repository's numbering).

  It is deliberately NOT "fail when the docs cite a closed issue". All 27
  citations in this package resolve to closed issues, because the docs earn
  their keep by explaining why the code is shaped as it is; that check would
  fire on everything and be suppressed the same day. What rots is the CLAIM
  around the citation, so the claim is what is recorded.

  **The ledger is keyed by a digest of the citing SENTENCE, not by file and
  issue number.** The first version keyed at `<file>#<number>` and review on
  PR #66 killed it with the obvious mutation: reword `doc.go`'s
  "`SealedEnclave.Openable` is the explicit probe (issue #33)" into "an
  openability probe is tracked as issue #33" — the exact defect this guard
  exists for — and it PASSED, because `doc.go#33` was already classified and
  nothing looked at the prose. A second sentence in the same file presenting
  the same issue as pending went through the same hole. With a sentence-level
  key a classification covers exactly the words classified: reword it and the
  old entry orphans while the new one is undeclared, so the suite fails twice
  until someone re-reads the sentence. Rewrapping a paragraph changes nothing,
  because the digest is taken after whitespace and comment markers are
  normalized away.

  Two halves, each with teeth on its own. The offline half compares the
  citations found in the tree against the ledger and fails on any difference in
  either direction. It needs no network. The online half resolves every
  `classPending` entry against Gitea and fails if the issue is closed.

  **The online half skips only for genuine transport unavailability.** A
  rejected token, a wrong repository or a malformed endpoint is a
  configuration failure and FAILS the suite rather than disabling the check
  while printing green — the second finding on PR #66, and the
  silent-instrument pattern this repository keeps catching. Setting
  `ENCLAVE_ISSUE_API` is what asks for the check; leaving it unset is the
  opt-out, so nobody's build breaks over a credential they did not ask for.

  An intermediate design warned instead of failing when nothing was
  `classPending`. It was removed after measuring that the warning could never
  be seen: a PASSING test in a non-verbose run emits nothing at all — not
  `t.Log`, not `os.Stderr`, not `os.Stdout` — and neither `ci.yml` nor
  `make test` runs `go test -v`. A state nobody can observe is not a state,
  and an invisible warning is the same defect one level up from the one this
  guard is for.

  **Merging #64 found two more extractor defects, and both were the silent
  kind.** `providertest` writes `PKCS#11` twice, which a bare `#(\d+)` reads as
  a citation of issue 11 — a guard that invents citations gets its ledger
  padded with nonsense until someone deletes the check. And `providertest`
  lives in a subdirectory, which the root-only file scan never read, so a whole
  new package's docs were excluded while the scan reported clean. A `#`
  preceded by a letter or digit is now part of a word rather than a citation
  unless the token before it looks like `owner/repo`, the file walk is
  recursive, and `TestCitationExtraction` and
  `TestDocIssueRefFilesReachesSubpackages` pin both. Walked paths are
  normalized with `filepath.ToSlash`, since the ledger is checked-in text and
  must not classify the same tree differently depending on the host separator.

  **The repository is checked on every lookup, not just the control.** The
  control proves the endpoint answers for this repository; it does not prove it
  does so for every number, and the pending loop branched on `state` alone. An
  endpoint, proxy or mistyped base serving the control correctly and a pending
  issue from elsewhere would have reported the docs verified against the wrong
  tracker — the same asymmetry as the control check, one level down. A
  wrong-repository answer is now a failure and does not count towards
  `Checked`, because it resolved nothing.

  The guard states what it CANNOT catch, in its own doc comment: it records
  the claim a human made about a sentence, not the claim the sentence makes,
  so a careless `classHistorical` defeats it; a forward reference carrying no
  issue number is invisible; and the online half is opt-in through the
  environment.

  **The online half's own policy is now tested, hermetically.** It was not,
  and that was the third finding on PR #66: with no `classPending` entries and
  `ENCLAVE_ISSUE_API` unset, the default run skipped, so the control lookup,
  the pending lookup, HTTP and auth failure, a malformed response, a closed
  pending issue, and the fatal branch of the policy itself were covered by
  nothing. A regression turning any of them fail-open would have left
  `go test ./...` green — the defect this guard exists to prevent, living
  inside the guard.

  The decision is now a VALUE: `evaluateIssueState` returns what should happen
  and why, and the test function only translates that into a skip, a log or a
  failure. `TestIssueStatePolicy` walks 18 rows against a stubbed
  `http.RoundTripper` — no network, no Gitea, no credentials, and not even a
  loopback port, since a guard whose own tests need a listening socket cannot
  run in a socket-restricted runner — asserting the action AND a fragment of
  its explanation, so a row cannot pass by producing the right verdict for the
  wrong reason. `misconfigured` remains the single place the fatal-versus-
  warn split is decided, and `TestMisconfiguredIsTheOnlyFatalWarnDecision`
  pins that every misconfiguration path routes through it.

  Two fail-open paths were found by that table and by review while writing it.
  An `ENCLAVE_ISSUE_API` with no scheme — `gitea.local/api/v1/...` — is
  accepted by `http.NewRequestWithContext` and refused by `http.Client.Do`, so
  it took the SKIP path under the very policy meant to catch it; the base URL
  is now validated up front. And narrowing "transport failure" to `net.Error`
  was not enough on its own, because `*url.Error` — which the client wraps
  EVERY failure in — implements `net.Error` itself, so the check matched
  unconditionally and classified everything as transport. The inner error is
  what is asked now. The second defect was caught by the table row written for
  the first.

  A third: the instrument check asserted only that the control issue is
  closed, which identifies no repository — measured on this server,
  go-blockstore, go-luks2, go-quicbaas and go-qrdb all have a closed #17 too,
  so a probe aimed at any of them would have passed and then resolved
  `classPending` entries against unrelated issues whose numbers merely
  collide. The control now also requires `repository.full_name` to be this
  repository, and that is verified live: pointed at go-blockstore with a valid
  token, it fails.
- **`Allocator`'s cacheline budget is asserted rather than assumed (#60).**
  This type's lock-free argument rests on `free` and `limit` sharing a line that
  nothing unrelated writes, and nothing enforced it. The slack ran out
  invisibly: the `stalled` seam (#51) costs 8 bytes and `rlimitBound` (#53)
  costs 1, but `rlimitBound` lands at offset 48 and a func pointer needs 8-byte
  alignment, so the bool drags 7 bytes of padding and the pair takes the struct
  from 56 bytes to exactly 64. Each diff looked free in isolation; the bill only
  existed in the combined struct, which came into being at a rebase, so no
  reviewer of either pull request could have been shown it. `TestAllocator_StaysWithinItsCachelineBudget`
  now fails on the next field of any size — measured: one added `bool` takes it
  to 72 bytes and the test names it — and separately fails if `free` and `limit`
  are ever split across lines.
- **The parked withdrawal no longer leaks on the handoff test's failure path
  (#60).** It parks inside `withdrawLocked` and therefore parks HOLDING `a.mu`,
  since `SetLimit`'s deferred `Unlock` has not run; a `t.Fatalf` between the park
  and the release left that goroutine blocked for the life of the process,
  holding a lock, with nothing joining it. Released through an idempotent
  `sync.Once` on `t.Cleanup` now. Exercised rather than argued: with `reserve`
  mutated to refuse every admission, the test fails on that exact line and the
  cleanup runs.
- **The retune/admission race test no longer inherits the scheduler's luck
  (#51).** `TestAllocator_Retune_RacesAdmission` ran a storm — goroutines
  allocating and destroying in a loop against goroutines raising a page and
  taking it back — and read the outcome off the counters afterwards. Which half
  of the race got to run was entirely the scheduler's to decide. Measured on one
  8-core host with no change to the code under test: `lowered=43` of 2400 idle,
  `lowered=2400` of 2400 under CPU load, and a flat
  `admitted=600 refusedAdmit=1800 lowered=2400` under `GOMAXPROCS=1` and
  `taskset -c 0`, which is not a race at all but sixteen goroutines run to
  completion in turn. On a saturated CI runner the shrinking half starved
  outright (`raised=2400 lowered=0`) and the test's own vacuity control fired on
  an unrelated pull request. **The control was right** — without it that run
  would have been a green report on a retune path that performed no lowerings —
  so the setup was fixed and the control kept, word for word.

  The contest is now ARRANGED. Each round releases a fixed cast from one line:
  actors that each attempt exactly one page-sized admission, actors that each
  destroy exactly one pre-held enclave, and one retuner that withdraws exactly
  one page. Every claim is one page and nothing loops, so supply and demand are
  known before the round opens and `min(supply, demand)` claims must be granted
  whatever order they land in — too many is the over-commit, too few is a
  starved round saying so instead of quietly proving less. Three shapes: one
  where supply covers demand (so a successful lowering is guaranteed on every
  host, which is what makes the control stop being load-sensitive), one two
  pages short (the conservation check), and one where destroys land inside the
  window. Measured 0 failures in 25 runs in each of multi-core, `GOMAXPROCS=1`,
  `taskset -c 0`, and under 16 busy loops, with `lowered` never below 546 of 600
  — against a structural floor of 400 that no scheduling can take away.
- **The linearization defect is now caught deterministically rather than a
  third of the time.** Arranging the contest fixed the vacuity, but neither form
  reliably catches the regression the test exists for: against a
  `withdrawLocked` reduced from compare-and-swap to read-then-subtract, the
  storm form went red on 3 runs in 10 and the arranged form on 0 in 10 — the
  window a racing admission must land in is two instructions wide, so entering
  it is a coin flip. `TestAllocator_Retune_LoweringLosesTheContestedPage` parks
  the withdrawal in that window through a seam on `Allocator` (`stalled`, nil in
  every build, called only from `withdrawLocked` under the retune mutex — never
  on the lock-free admission path), lands the conflicting admission by hand, and
  only then releases it. Red 25 out of 25 against that regression, multi-core
  and `GOMAXPROCS=1` alike, reporting `free = -4096` — the over-commit itself,
  by name.


## [v0.4.0-alpha] - 2026-08-26

### Added

- **`WipeAll() (int, error)` — a cooperative shutdown sweep that destroys every
  live enclave, reports how many it could not, and reports whether any of them
  were corrupt.** For an orderly exit: a signal handler, a defer in main. It is
  not a fault handler and nothing calls it for you.

  The two return values are **orthogonal, and neither implies the other**. The
  count is how many enclaves are still holding locked memory; a non-zero value
  is a shutdown-ordering bug in the caller. The error reports detected canary
  corruption and nothing else, matching `ErrEnclaveCorrupted` through
  `errors.Is` exactly as `Destroy`'s panic value does, and naming how many
  enclaves failed.

  A corrupt enclave's pages **are** reclaimed, so it is not "still held" and
  never appears in the count — which is precisely why the corruption needs a
  return value of its own. An earlier revision of this branch returned only the
  count, so a sweep that detected memory corruption reported `0` and looked like
  a clean exit: `Destroy` panics on that same condition because it matters, and
  a sweep must not abort, but non-fatal must not mean invisible either.

  This is the one thing v0.3.0-alpha's removal of memguard left a consumer
  needing. Option B deleted memguard's process-global registry because of what
  memguard did WITH it — purge the whole thing on any mapping failure, then panic
  — while a consumer had been relying on that same registry for a *cooperative*
  exit wipe. After the conversion its exit path silently stopped covering the
  key it was meant to destroy: nothing failed, nothing announced it.

  A cooperative sweep is a different mechanism wearing a similar shape.
  `WipeAll` is called explicitly rather than triggered by a fault, **never
  panics** — a sweep that aborted partway would leave every enclave after the
  failure untouched — and **never waits on a reader**: an enclave being read
  when the sweep reaches it is retried on a later pass, and only one still held
  after every pass is counted, because a shutdown that hangs behind a goroutine
  still reading a key is worse than one that reports what it could not reach.

  The registry is touched on construction, on destruction, and by `WipeAll` — and
  by **nothing on the borrow path**, which is what keeps `purgeMu` from coming
  back. Allocating inside a live borrow still works.

### Changed

- **`WipeAll` waits briefly between retry passes, so the promise it makes about
  momentary readers is actually true.** Without it the retry loop was
  temporally degenerate: all eight passes completed in about 966 **nanoseconds**,
  so "still held after every pass" meant "held for more than roughly a
  microsecond," and a realistic reader — a health probe calling `IsAlive`, a
  `Size`, an `EqualTo` — lost its enclave 20/20 times at every duration from
  20µs to 2ms.

  This is a backoff, not synchronization, and the distinction is the test:
  remove the wait and the sweep is still **correct** — the enclave simply is not
  reclaimed on that call, the count stays honest, and the documented remedy
  still works. A sleep standing in for an ordering guarantee becomes *wrong*
  when removed; that is the pattern this project bans, and this is not it. There
  is also nothing to wait on: the party being waited for is another goroutine's
  read lock, and `sync.RWMutex` exposes no "notify when free."

  Cost is milliseconds at shutdown, and only when something is genuinely still
  held. Stated as measured rather than as arithmetic: nominally 1.4ms, measured
  at **7.5ms** against a held enclave, because short sleeps overshoot.
- **`WipeAll`'s documentation no longer attributes a non-zero count solely to
  caller ordering.** A read that simply outlasts the retry budget produces the
  same number, so the count now reads as "these were still in use" rather than
  as a diagnosis — and it says plainly that `WipeAll` belongs to the **program
  that owns the process**, never to a library, since it destroys enclaves
  belonging to subsystems a library knows nothing about. Two independent
  consumers reached that conclusion on their own and declined to call it; an API
  two callers separately avoid is inviting the mistake.
- **An enclave is published to the shutdown ledger as the LAST step of its
  construction**, after every field a sweep reads has been set. `Allocator.New`
  and `Allocator.NewSized` install the reservation callback and then register;
  the constructors no longer register on their behalf.

  Registering inside the constructor put an allocator-backed enclave on the
  ledger while `Allocator.New` had not yet assigned its `release` callback. A
  `WipeAll` landing in that window read the field while it was being written — a
  data race — and destroyed the enclave with `release` still nil, handing the
  pages back to the kernel while the budget kept the charge. In the
  `WipeAll`-at-exit pattern, where the sweep is the destroyer, nothing ever
  returns that charge: an `Allocator` that sweeps and keeps running loses
  admission capacity permanently. Measured on the defective shape, 34–52 MiB of
  a 256 MiB budget was stranded per run.

  No API change; `WipeAll` and both allocator constructors behave as documented.
- **A momentary reader no longer costs an enclave its sweep.** `WipeAll` retries
  an enclave it could not lock on its next pass, instead of writing it off after
  one lost race.

  `tryReleaseMapping` takes the WRITE lock without waiting, so it loses to any
  concurrent reader — `IsAlive`, `Size`, `EqualTo`, a health probe polling an
  enclave during shutdown — not merely to a long `WithBytes` borrow. The sweep
  marked every enclave as seen when it built a pass's batch, *before* trying to
  release it, so one lost microsecond took that enclave out of the sweep
  permanently: no later pass reconsidered it, the process exited with the
  material still mapped and locked, and the returned count blamed the caller's
  shutdown ordering. That is the outcome `WipeAll` exists to prevent, reached
  through the most ordinary concurrent operation there is.

  Termination never depended on the seen-set — `maxSweepPasses` is the bound —
  so it is gone. A genuinely long borrow still outlives every pass and is
  skipped and counted, which remains correct: memory being actively read must
  not be unmapped underneath the reader.
- `tryReleaseMapping` now returns `(released bool, err error)` rather than
  `(error, bool)`, putting the error last as the conventions require.

### Documentation

- **`WipeAll` is documented in the API surface**, in both the README table and
  the package doc, where it was missing entirely.
- **The README's "enclaves are destroyed when their owner destroys them and at
  no other time" is corrected.** It became false the moment a global sweep
  existed. What remains true — and is what the sentence was protecting — is that
  nothing destroys an enclave in reaction to a *fault*.
- **`Open` names `WipeAll` as a second concurrent destroyer.** A retained `Open`
  slice segfaults if a shutdown sweep runs while the caller still holds it, and
  only this enclave's own `Destroy` was mentioned before.
- **The constructors document that a successful return can hand back an
  already-destroyed enclave** when `WipeAll` ran between publication and return.
- **The registry design note states its two costs plainly:** `registryMu`
  serializes construction and destruction process-wide (it is not `purgeMu` — it
  never touches the borrow path and is never held across a syscall or an enclave
  lock), and an enclave whose release keeps failing is retained for the process
  lifetime by design, so a later sweep can retry it.

### Tests

- **The never-panics guarantee is now pinned rather than merely documented.**
  `WipeAll`'s most prominent promise — that it does not panic, including on an
  enclave whose canary fails — had no test. A corrupt canary is now seeded into
  a batch and the whole batch is checked: no panic, every enclave wiped, the
  sweep not aborted at the failure, the corrupt enclave's reservation returned
  (a detected corruption still counts as released), and the corruption
  **reported** through the error rather than swallowed.
- **The concurrent-construction test was rebuilt to be affordable in CI.** Its
  first two versions needed a large payload (1 MiB, then 512 KiB) to widen the
  window they race for, and a sweeper that spun without yielding to sample it
  often. Both worked locally — including pinned to a single CPU — and both blew
  the test's own drain bound on the build runner, twice.

  The payload was the expensive half: under `-race`, hundreds of megabytes of
  mlock churn in a memory-capped container is a different order of problem from
  slow CPU. The width also turned out to be unnecessary — race detection needs
  the window ENTERED, not held open, and a one-page payload hits it just as
  reliably (8/8 against the defective shape) for 1/128th of the memory. The test
  now costs hundredths of a second on every machine measured.

  The strength that bought moved to the race detector, which is the reliable
  oracle for this defect and is what CI runs; the budget assertion is kept as a
  weaker second signal that needs no detector, and the doc comment says so
  rather than claiming two equal oracles. The "a live successful return is
  usable" check moved to a quiescent phase, because it is a property of
  construction rather than of the race — asserted against a live sweeper it
  failed whenever the sweeper won everything, which on one CPU was 99 times in
  100.
- **The failed-release path is pinned.** An enclave whose release fails for a
  reason that is not corruption keeps BOTH its Allocator charge and its ledger
  entry. Neither was held by any test. Refunding unconditionally would hand the
  budget back while the kernel still holds the pages, so the allocator
  over-admits against a real `RLIMIT_MEMLOCK`; deregistering would make
  `WipeAll` return **zero while the material is still mapped and locked**, and
  no later sweep could ever find it — the same class as the tallied-count
  fail-open. The shipped code was correct on both; nothing held it correct.
- **The corruption contract is pinned in both directions.** One test requires
  the error to name how many enclaves were corrupt; a control requires a clean
  sweep to report `nil`, without which both would pass against an
  implementation that reported corruption unconditionally. Every other test in
  the package now routes its sweep through a helper that fails on an unexpected
  corruption report, so the whole suite doubles as that control.

## [v0.3.0-alpha] - 2026-08-26

### Changed

- **go-enclave maps its own memory.** The backing store is no longer a memguard
  `LockedBuffer`; the package allocates, locks, guards, wipes and releases pages
  through `memcall` directly — the layer memguard itself uses.

  The layout is deliberately unchanged: an mlock'd inner region with the data
  flush against an inaccessible postguard, a random canary in the slack ahead of
  it, a second guard page in front, wipe-and-verify on release. What changed is
  the FAILURE POLICY, which could not be changed from outside memguard. memguard
  registers every buffer in a process-global list and answers any mapping failure
  with `core.Panic`: `Purge()` — destroying and UNMAPPING every live buffer in
  the process — and then a panic. go-enclave converted that panic into a typed
  error from v0.1.0-alpha, but a `recover` cannot undo a purge that already ran,
  so it also needed `purgeMu`, a process-wide lock serializing every allocation
  against every borrow.
- **`purgeMu` is gone, and with it the nested-allocation deadlock.** Allocating,
  borrowing or destroying an enclave from inside another enclave's live borrow
  now works. It previously deadlocked: allocation took the lock exclusively,
  borrows took it shared, and Go's `RWMutex` blocks new readers once a writer
  queues. That blocked an ordinary shape outright — handing borrowed key
  material to an injected interface whose implementations allocate protected
  memory of their own — because the three ways of writing the code were
  deadlock, an unprotected heap copy, or an unsynchronized read.
- **An allocation failure no longer damages unrelated enclaves.** Exhausting
  `RLIMIT_MEMLOCK` fails exactly the allocation that reached the ceiling. An
  enclave is destroyed when its owner destroys it and at no other time, so
  `ErrEnclaveDestroyed` can no longer appear spontaneously on an enclave the
  caller still holds.
- **A failed mapping releases everything it took.** Where memguard aborts and
  never unwinds, this returns an error — so the cleanup is real code, verified
  against `VmLck` and the process's VMA count over 256 induced failures.
- **The material is destroyed before any syscall that could be refused.**
  `mprotect` can be denied — a seccomp filter is the realistic case — and the
  release path used to make the region writable first and wipe afterwards, so a
  refusal returned an error having wiped nothing and left the secret resident on
  locked pages. While the inner region is writable, which it is unless a freeze
  succeeded, the material needs no syscall to destroy; it is now destroyed
  first, so the worst a refusal can cost is an empty mapping that could not be
  handed back.
- **A release that could not unmap keeps its handle.** If the region cannot be
  made writable — so it was never wiped — or cannot be unlocked or unmapped, the
  mapping is left intact and the `Allocator` reservation is NOT returned.
  Clearing the fields regardless would strand memory that is still resident,
  possibly still locked and possibly still holding material, with no reference
  left to retry through, while the budget reported those bytes as available. A
  caller that recovers from the panic can call `Destroy` again to retry.
- The `Allocator` is unchanged in shape but its rationale is narrower and
  honest: it bounds one path's consumption so an untrusted source cannot starve
  the rest of the process. It never protected against collateral purges, and
  there are no longer any to protect against.

### Added

- `CoreDumpsDisabled()` reports whether lowering `RLIMIT_CORE` at import
  succeeded. The package documented core dumps as disabled while discarding the
  result, which is a guarantee the code did not enforce and a control callers had
  no API to assert. It is best effort by nature, so it is now reported rather
  than promised — and every enclave's pages are separately marked
  `MADV_DONTDUMP` as they are locked, which **is** verified and fails the
  allocation if refused. memcall attempts the same madvise and discards its
  result, so this is the first core-dump control here that is actually checked.
- `ErrEnclaveCorrupted`, reported when the canary does not verify on release.
  `Destroy` wipes and releases everything it holds, returns the `Allocator`
  reservation, and then panics with it — see its documentation for why detected
  memory corruption is the one condition this package does not hand back as an
  error.

### Removed

- The `github.com/awnumar/memguard` dependency, and with it `golang.org/x/crypto`
  — go-enclave never called memguard's `Enclave`/`Seal` paths, but their NaCl
  secretbox sat in the build graph of every consumer, and x/crypto is where the
  ten HIGH CVEs cleared in v0.2.0-alpha came from. The module now requires
  `memcall` and `golang.org/x/sys` and nothing else.

## [v0.2.1-alpha] - 2026-08-26

### Fixed

- **`Allocator` admitted against the wrong unit.** The budget counted requested
  BYTES while the kernel charges locked PAGES, so a budget sized below
  `RLIMIT_MEMLOCK` was not actually bounded by it — the comparison the type
  exists to make could not be made. Measured against `/proc/self/status` VmLck
  on a 4 KiB-page host: a 32-byte enclave locks 4096 bytes, a **128x**
  undercount, and 200 of them charged 6400 bytes against a budget while locking
  819200. Reservations are now charged, reported and released in locked bytes,
  page-rounded as the kernel charges them.
- **A size too large to MAP reached memguard and purged the process.** memguard
  lays out the data region plus two guard pages using `int` arithmetic
  (`core.NewBuffer` asks `memcall.Alloc` for `2*pageSize + roundToPageSize(size)`),
  so past a certain size that arithmetic overflows, `mmap` refuses the nonsense
  length, and `core.Panic` destroys every live locked buffer in the process.
  Measured on v0.2.0-alpha with `n = MaxInt64-pageSize`: admission passed, the
  request reached memguard, and an unrelated canary enclave came back dead. Both
  construction paths are now gated — `Allocator.NewSized` through admission and
  `NewMemoryEnclaveSized`, which has no allocator in front of it at all.

### Added

- `LockedSize(n int) int64` — the locked memory an enclave of n bytes actually
  consumes, so a caller can size a budget instead of guessing. Returns int64 to
  match `NewAllocator`'s budget, so sizing one needs no conversion. Guard pages are
  not part of it: they are mapped PROT_NONE and never mlock'd, verified against
  the kernel's accounting rather than inferred from the mapping code.

### Changed

- `ErrInvalidSize` now reports two conditions rather than one: a non-positive
  size, and a size too large for memguard to map. Its message changed to match.
  A larger `Allocator` budget helps with neither, which is why they are not
  `ErrBudgetExhausted`.
- `Limit`, `InUse`, `Available` and `BudgetError.Requested` are documented as
  **locked bytes**, comparable to `RLIMIT_MEMLOCK`. Existing budgets therefore
  admit far fewer enclaves — which is the fix, not a regression: they admitted
  more before only by mismeasuring. A budget below one page constructs and then
  admits nothing, refusing with figures that show why.

## [v0.2.0-alpha] - 2026-08-26

### Added

- `NewMemoryEnclaveSized(n int)` and `Allocator.NewSized(n int)`: locked, zeroed
  memory of `n` bytes that the caller fills IN PLACE through the existing
  `WithBytes` borrow, so generated material — a drawn key, a derived wrapping
  key, a Shamir share — never exists on the ordinary heap, not even transiently.
  Until now the whole construction surface took existing bytes, which forced
  callers into the `make` + generate + move shape the wipe cannot fully undo.
- `ErrInvalidSize` for a non-positive size, mirroring `ErrInvalidBudget`.
  `Allocator.NewSized` refuses it at the admission gate, before memguard is
  entered.

### Changed

- `Allocator`'s admission gate is now a single `reserve` step shared by `New` and
  `NewSized`, and it refuses a non-positive reservation outright — the byte
  counter can no longer be driven below zero, which would have let a concurrent
  caller admit against an inflated budget.
- The admission predicate compares the request against the remaining budget
  instead of testing `used + n` against the limit. The addition overflows int64
  for a large enough request and wraps negative, which passed the budget test and
  admitted an allocation the budget could not cover — a fail-open into memguard,
  reachable through `NewSized` because it takes its size from the caller as a
  plain int rather than as the length of an already-allocated slice.
- Documented the one property that separates the two construction paths after
  construction: memguard freezes the pages of an enclave built from existing
  material, while a sized enclave's pages stay writable for its lifetime. `Open`
  and the package documentation previously said a write always faults.

### Security

- Bumped the indirect `golang.org/x/crypto` from v0.41.0 to v0.52.0, clearing ten
  HIGH CVEs (CVE-2025-47913, CVE-2026-39828/-39829/-39830/-39831/-39832/-39835,
  CVE-2026-42508, CVE-2026-46595, CVE-2026-46597). No go-enclave code imports the
  module — it arrives via memguard — so `govulncheck` reported them only as
  present-but-uncalled; `trivy` is module-level and does flag them.
- Added a tracked, intentionally empty `.trivyignore`, and pointed the `Makefile`'s
  `trivy` target at it. The nightly Trivy job passes `--ignorefile .trivyignore`,
  and trivy treats a missing ignore file as a FATAL flag error rather than as an
  empty list — so that job had never scanned this repository, and the CVEs above
  were behind the error it died on.

## [v0.1.0-alpha] - 2026-08-23

### Added

- Initial release. `MemoryEnclave`, a region of locked, zeroized memory for
  holding sensitive material for its whole lifetime in the process. Extracted
  from an object-storage library that had grown its own copy, so that libraries
  handling key material can share one implementation instead of each rolling
  their own.
- Error-returning locked-memory handling: an mlock failure yields a typed
  `LockedMemoryError` / `ErrLockedMemoryUnavailable` instead of memguard's
  process-wide `Purge` + panic.
- The `WithBytes` borrow window and process-wide `purgeMu` coordination, so an
  in-flight borrow survives a purge triggered elsewhere in the process.
- Admission control: `Allocator`, a lock-free bounded allocator with a typed
  `ErrBudgetExhausted` / `BudgetError`, so callers can cap unauthenticated
  locked-memory allocation below the RLIMIT_MEMLOCK ceiling that triggers a
  purge. Reservations are released on `Destroy`.

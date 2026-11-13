# Contributing to go-enclave

Thank you for helping. This page covers building and testing a change,
changelog fragments and the naming rule. Releases are cut by a maintainer, as
[docs/build-and-release.md](docs/build-and-release.md) describes.

To report a security issue, do not open an issue or a pull request. Follow
[SECURITY.md](SECURITY.md).

## Requirements

- Go 1.27.4 or later.
- Linux to run the tests. The BSDs and Windows are build-only
  ([test status](docs/memory-enclave/engineering.md#test-status)).
- Docker, for the integration suite and the devcontainer targets.
- `jq`, for `make check-scripts`.
- `swtpm` and `swtpm-tools`, only for `make integration-test-tpm`.

The analysis tools (golangci-lint, gosec, govulncheck, trivy, shellcheck,
actionlint) are pinned with SHA-256 checksums in `scripts/tool-pins.sh`. `make`
uses a verified copy on `PATH`, or installs the pinned version into
`bin/tools/`. The devcontainer's `toolchain` image carries Go and every pinned
tool, and every gate passes in it offline:

```sh
make docker-build
make docker-run CMD='make test'
```

## Unit-test prerequisites

The unit suite allocates real locked memory and has no skip guards. Where an
environment falls short, it fails at startup with one message instead of
skipping tests. It needs:

- a soft `RLIMIT_MEMLOCK` of at least 2 MiB, or unlimited. With
  `CAP_IPC_LOCK`, the hard limit must also be at least 2 MiB, because the
  fault-injection tests drop the capability and then raise the soft limit to
  the hard one. Raise it with `ulimit -l 2048`, or `--ulimit memlock=…` for a
  container;
- a readable `/proc`;
- permission to lower its own resource limits.

## Make targets

| Target | What it does |
|---|---|
| `make test` | Unit tests with `-race` across `-cpu=1,2,8`, then the backend modules' unit tests |
| `make coverage` | The same run with coverage. Fails when any package, or the total, is below 90% |
| `make coverage-report` | An HTML report at `coverage/coverage.html`, with no threshold |
| `make test-fips` | Build and test under `GOFIPS140=latest GODEBUG=fips140=only` ([FIPS 140-3](docs/sealing/engineering.md#fips-140-3)) |
| `make test-runtimesecret` | Unit tests built with `GOEXPERIMENT=runtimesecret`, which turns on key-schedule erasure |
| `make bench` | Benchmarks with allocation counts |
| `make lint` | gofmt, golangci-lint (vet, staticcheck, gosec), actionlint and shellcheck |
| `make security` | gosec, govulncheck, `go mod verify` and trivy |
| `make vuln` | govulncheck |
| `make build` | Compile every package |
| `make cross-build` | Compile, vet and link the test binaries for every supported GOOS/GOARCH, including 32-bit and `android/arm64` |
| `make lint-gates` | The repository's own checks in `build/ci/buildgates`: action pins, the feature map, changelog assembly and the scripts |
| `make ci-fast` | Every gate that does not need Docker |
| `make ci` | The full local gate. A pull request must pass it |
| `make help` | Every target and variable |

Run the package or feature you are changing, not the whole suite:

| Target | Scope |
|---|---|
| `make test-<pkg>`, `make coverage-<pkg>` | One package: `enclave` (the root), `providertest`, `backendtest` or `memscan` (`internal/memscan`) |
| `make bench-enclave` | The root package's benchmarks |
| `make test-<feature>` | The unit tests of one feature, a directory under `docs/` such as `sealing` or `linux-secretmem` |
| `make test-backends` | The unit tests of `backends/tpm` and `backends/armtrustzone` |

Pass extra test flags with `TESTFLAGS`, for example
`make test-enclave TESTFLAGS=-run=TestSealer`. `-race` is kept.

## Integration tests

The integration suite is `test/integration/enclave/`, behind the `integration`
build tag. It never runs on the host: each target runs it in the devcontainer.

| Target | What it runs |
|---|---|
| `make integration-test` | The whole suite |
| `make integration-test-fips` | The whole suite under FIPS 140-3 strict mode |
| `make integration-test-<feature>` | The tests of one feature only |
| `make integration-test-userns` | The user-namespace test, under a seccomp profile that permits `CLONE_NEWUSER` |
| `make integration-test-tpm` | `providertest` against the TPM provider on a throwaway `swtpm`, on the host |
| `make integration-test-arm-trustzone` | `backendtest` and `providertest` against the arm-trustzone backend, in the guest of the pinned OP-TEE fixture image (`make optee-fixture-image` prints it) |

Every integration test is named with its feature's prefix, such as
`TestSealing_` or `TestLinuxSecretmem_`, and `scripts/features.map` maps each
feature to its prefix and source files. A new `docs/<feature>/` directory needs
a line there, or `make lint-gates` fails. Which test covers which feature is
listed in [test/integration/COVERAGE.md](test/integration/COVERAGE.md).

## Changelog fragments

Do not edit `CHANGELOG.md`. A change that callers can see adds or edits one
fragment, `changelog.d/<feature>.md`, where `<feature>` is the feature's name
in the [SPEC](docs/SPEC.md) feature table, the same as its `docs/<feature>/`
folder. Every pull request on that feature edits the same fragment. The
release folds the fragments into `CHANGELOG.md`.

A fragment holds one or more entries under Keep a Changelog headings (`###
Added`, `### Changed`, `### Deprecated`, `### Removed`, `### Fixed`,
`### Security`):

```markdown
### Added

- **linux-secretmem**: `NewSecretMemory` returns a backend whose pages are memfd_secret memory. ([#123](https://github.com/jeremyhahn/go-enclave/issues/123))
```

- Write the outcome for a caller in at most two sentences, and link the
  issue. The issue and the pull request carry the detail; the entry lists no
  files and describes no mechanism.
- Mark a breaking change under `### Changed`, start the entry with
  `**BREAKING** <feature>:`, and link the migration note in
  [docs/README.md#upgrading](docs/README.md#upgrading). The migration steps
  live there, not in the changelog.
- CI, workflow, lint, test-only, refactoring and docs-only changes get no
  entry, nor does anything that changes nothing for callers. A raised
  minimum Go version, a security fix, a dependency change that affects
  consumers and a change of supported platforms do get one.

## Naming

The types describe their mechanism, locked memory, and not their contents. Do
not introduce `Secret`, `SecureString`, `SecureBytes` or `ProtectedBuffer`
synonyms.

## Nested modules

`backends/tpm` and `backends/armtrustzone` are Go modules of their own. Each
requires a released version of the root module, and the root never requires
them, so the root module keeps a single dependency. Do not add a `replace`
directive or a `go.work` file; the Makefile sets `GOWORK=off`.

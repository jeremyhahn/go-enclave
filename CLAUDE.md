# go-enclave

Locked, guarded memory for key material in Go, with sealing at rest. This file
is for contributors and coding agents. `AGENTS.md` and `CLAUDE.md` carry the
same text: change both in the same commit.

Start with [README.md](README.md) for the API and
[CONTRIBUTING.md](CONTRIBUTING.md) for the full target list and the changelog
rules.

## Build, test and coverage

| Command | Use |
|---|---|
| `make test-<pkg>` | One package with `-race` across `-cpu=1,2,8`. `<pkg>` is `enclave` (the root), `providertest`, `backendtest` or `memscan` |
| `make test-<feature>` | One feature's unit tests; features are the directories under `docs/` that `scripts/features.map` lists |
| `make test` | Every package, then `make test-backends` (the `backends/*` modules) |
| `make coverage` / `make coverage-<pkg>` | Coverage; fails when any package or the total is below 90% |
| `make test-fips` | Build and test under `GOFIPS140=latest GODEBUG=fips140=only` |
| `make test-runtimesecret` | Unit tests under `GOEXPERIMENT=runtimesecret` |
| `make lint` | gofmt, golangci-lint, actionlint, shellcheck |
| `make lint-gates` | The repository's own checks in `build/ci/buildgates` |
| `make integration-test` / `make integration-test-<feature>` | The integration suite in the devcontainer (needs Docker); never on the host |
| `make integration-test-tpm` | The TPM provider against `swtpm`, on the host |
| `make integration-test-arm-trustzone` | The arm-trustzone backend in the pinned OP-TEE fixture image |
| `make ci-fast` / `make ci` | The full gate without Docker / with Docker |
| `make docker-run CMD='make test'` | Any target in the pinned toolchain image, offline |

Run the package or feature under change, not the whole suite. The unit suite
needs a soft `RLIMIT_MEMLOCK` of at least 2 MiB and a readable `/proc`, and
fails at startup without them ([prerequisites](CONTRIBUTING.md#unit-test-prerequisites)).

## Rules

- No skip guards and no `-short`. A test that cannot run fails.
- Errors the API returns are typed: an exported sentinel that callers match
  with `errors.Is`, and a struct type with `Is` and, where it wraps, `Unwrap`
  when the caller needs detail (see `errors.go`).
- In the root package, constructors return interfaces and concrete types stay
  unexported.
- Importing a package registers nothing. `main` calls `Register`.
- The root module depends only on `golang.org/x/sys`. `backends/tpm` and
  `backends/armtrustzone` are separate modules that require a released root,
  never the reverse. No `replace` directives and no `go.work`: the Makefile
  sets `GOWORK=off`.
- Shipped source cites no issue numbers; `make lint-gates` checks this.
- Every non-test `.go` file of the root module, every integration test and
  every `docs/<feature>/` directory belongs to exactly one feature in
  `scripts/features.map`. Integration tests are named `Test<FeatureName>_...`,
  for example `TestSealing_` or `TestLinuxSecretmem_`.
- Coverage is at least 90% for every package of the root module. The backend
  modules' unit tests run, but their device paths need the device and are not
  held to the floor.
- Naming: types describe the mechanism (locked memory), not the contents. No
  `Secret`, `SecureString`, `SecureBytes` or `ProtectedBuffer`.
- A change callers can see edits `changelog.d/<feature>.md`
  ([rules](CONTRIBUTING.md#changelog-fragments)). CI, test and docs-only
  changes get no fragment.

## Build tags

No shipped package is gated by a custom build tag. `GO_BUILD_TAGS` must stay
empty; the Makefile refuses any other value.

| Tag | Selects |
|---|---|
| `integration` | The integration suite, `test/integration/enclave/` |
| `userns` | `memlock_userns_linux_test.go`, the user-namespace test (`make integration-test-userns`) |
| `optee` | The OP-TEE conformance tests in `backends/armtrustzone` and the OP-TEE harness in the integration suite |
| `swtpm` | The `swtpm` conformance tests in `backends/tpm` |
| `goexperiment.runtimesecret` | Set by `GOEXPERIMENT=runtimesecret`; builds `secret_erase.go` on linux/amd64 and linux/arm64 (not Android) |

The other constraints are GOOS and GOARCH: per-OS files such as
`memlock_bsd.go`, `madvise_unix.go` and `secretmem_linux.go` each have an
`_unsupported.go` counterpart.

## Layout

```
.                           package enclave: memory enclaves, Allocator, Sealed,
                            Sealer, backends, Detect, linux-secretmem, WipeAll
providertest/               conformance suite for KeyProtector and RootUnsealer providers
backendtest/                conformance suite for backends
backends/tpm/               TPM 2.0 KeyProtector (its own module)
backends/armtrustzone/      OP-TEE backend and KeyProtector (its own module)
internal/memscan/           process-memory scan the residue tests share (Linux)
testdata/fuzz/              fuzz regression corpus for the root package; go test reads it here
test/integration/           integration suite (enclave/) and COVERAGE.md
build/ci/buildgates/        the repository's own gates, as Go tests (its own module)
build/docker/devcontainer/  the toolchain and integration images
scripts/                    Makefile logic, tool pins (tool-pins.sh), features.map
changelog.d/                changelog fragments, one per feature
docs/                       documentation
```

Unit tests live beside their source.

## Documentation

- `docs/README.md` is the index, and holds the Upgrading notes for breaking
  changes.
- `docs/SPEC.md` lists every feature and its status. `ROADMAP.md`, at the
  root, agrees with it.
- Each feature has a folder `docs/<feature>/` with `user.md`,
  `architecture.md`, `engineering.md` and `api.md`.
- `docs/backends/` also holds the arm-trustzone design and the backend
  proposals. `docs/sealing/hardware-providers.md` is the TPM provider design.
- `docs/build-and-release.md` covers the gates, CI and releases.
- Pages carry a status banner (NORMATIVE or REFERENCE) and a
  `Last verified:` date. Where a page and the code disagree, the code is
  right: fix the page and update the date.

## Reference standards

Where a standard exists, go-enclave implements it as written and designs
nothing in its place. The text of each standard the code implements is copied
into [docs/reference/](docs/reference/README.md), with an index naming the
revision and the implementing code. A change that implements a new standard
adds its text and an index row there.

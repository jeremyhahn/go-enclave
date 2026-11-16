# Changelog

All notable changes to go-enclave are documented here. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

Each entry names one feature row of the [specification](docs/SPEC.md#features)
and states the outcome for a caller in one or two sentences. The linked issue
holds the detail. A breaking change is marked **BREAKING** and links its
migration steps in [Upgrading](docs/README.md#upgrading). Changes waiting for
the next release are in `changelog.d/<feature>.md`, one file per feature, and
the release folds them in here.

Releases v0.1.0-alpha through v0.11.1-alpha predate the public release. Their
notes are in the git tags and the
[GitHub release notes](https://github.com/jeremyhahn/go-enclave/releases).

## [Unreleased]

## [v0.12.0-alpha] - 2026-11-16

### Added

- **public-release**: Initial public release. It requires Go 1.27.4 or later and builds on Linux (including Android), the BSDs, darwin, iOS, illumos, Solaris, AIX and Windows, with Linux the only platform the tests run on.
- **memory-enclave**: `NewMemory`, `NewMemoryCopy` and `NewMemorySized` keep secret bytes in locked pages between guard pages, excluded from core dumps where the OS allows, readable only through a borrow, and wiped on release. `Freeze` makes a handle read-only, and `HardenProcess` is an opt-in process hardening step.
- **locked-memory-budget**: `Allocator` admits each enclave against a budget of locked bytes before it allocates, discovers `RLIMIT_MEMLOCK` and can be retuned at runtime.
- **sealing**: `Sealed` keeps an AES-256-GCM envelope at rest and opens only into a fresh, frozen enclave, with root-key and per-operation modes that work under FIPS 140-only mode. New seals write envelope version 2, and version 1 envelopes still open.
- **keyprotector-providers**: Sealing keys can be protected by the in-process `SoftwareProvider`, the TPM 2.0 provider in the `backends/tpm` module (Linux) or the TrustZone provider in the `backends/armtrustzone` module, whose trusted-application side is not yet released. A secure-element provider is not available yet.
- **shutdown-sweep**: `WipeAll(ctx)` wipes every live enclave and orphaned mapping, then sweeps registered `Sweeper` backends, and reports what it could not reclaim as one `*SweepError`.
- **provider-conformance**: `providertest.TestProvider` checks that a `KeyProtector` retains no key material, refuses tampered and forged blobs, honors its context and implements only the modes it claims.
- **backends**: A backend implements a small `Handle` and `Backend` core plus optional capabilities and is registered by name with `Register`, never on import. A missing capability is a `*CapabilityError`, never a fallback.
- **backend-conformance**: `backendtest.TestBackend` checks a backend's handle lifecycle, its capability claims in both directions, import wiping and evidence nonce binding.
- **build-and-release**: The root module's only dependency is `golang.org/x/sys`, and every gate is a Makefile target that runs offline with pinned, checksum-verified tools.
- **enclave-interface**: Constructors return the `Handle` and `Backend` interfaces, so no caller depends on a concrete backend type.
- **backend-detection**: `Detect(ctx)`, called from `main`, probes only the registered backends and selects the highest-ranked usable one, or the memory enclave when no other is usable.
- **linux-secretmem**: `NewSecretMemory` is a Linux backend that holds material in `memfd_secret(2)` memory, out of core dumps and the kernel direct map. On other systems it is a build-only stub, and detection keeps the memory enclave where the kernel refuses it.
- **open-in-secretmem**: `Sealed.OpenIn` decrypts straight into a linux-secretmem handle, so no scratch enclave or heap buffer holds the plaintext.
- **arm-trustzone**: The `backends/armtrustzone` module is a backend on OP-TEE over the Linux TEE driver; `Connect` opens a session to the trusted application, and `Random` fills enclaves from its random source.

- **arm-trustzone**: Tests cover `Backend.Close` over the fake TEE on both driver kinds, so a closed backend returns `ErrBackendClosed`, waits out a `Random` in flight and leaves no device, session or shared memory open. ([#347](https://github.com/jeremyhahn/go-enclave/issues/347))
- **arm-trustzone**: Tests cover `Backend.Random` over the fake TEE on both driver kinds, chunk by chunk, so a TA error, an INVOKE ioctl error or a cancel on any chunk returns no handle and leaves no shared memory live. ([#347](https://github.com/jeremyhahn/go-enclave/issues/347))
- **arm-trustzone**: Every exported error type and sentinel of `backends/armtrustzone` is held to one contract table test (messages, `errors.Is`, `errors.As` through `%w` and `errors.Join`, `Unwrap`), with a completeness check that fails on any exported error without a row. ([#375](https://github.com/jeremyhahn/go-enclave/issues/375))

- **backend-conformance**: `backendtest.CheckRefusal`, a check hardware backend modules share: on a host without their hardware, the constructor and probe must refuse with the module's typed unavailable error naming the failing step, register no backend and leave the locked-memory budget unchanged; each broken property is a `*PropertyError` (#330).
- **backend-conformance**: `backendtest.ExampleTestBackend` is a runnable example that certifies the shipped locked-memory backend with a minimal `Config`, and the backend conformance guide links it (#367).
- **backend-conformance**: `backendtest` holds every exported error type to one contract table: `Error()` on zero and populated values, `errors.Is` against every package sentinel, `errors.As` through `%w` and `errors.Join`, and `Unwrap`. A completeness check fails when an exported error type or `Err` sentinel has no entry (#376).

- **backends**: A race test drives the named backend registry from many goroutines, so concurrent `Register`, `Lookup` and `BackendNames` calls each register a name once, refuse duplicates with `*BackendExistsError` and return sorted, complete snapshots (#369).

- **build-and-release**: a build gate for `build/ci/release-tag.sh`: plain version tags such as `v1.2.3` and `v1.2.3-alpha.1` become exactly the `tag=` and `sha=` release outputs, and a branch ref, an empty or unset ref, or a tag holding shell metacharacters, spaces, slashes, quotes, backticks, `$(...)`, newlines or a leading dash is refused with nothing written and the name not echoed (#370).
- **build-and-release**: A build gate, `TestMarkdownRelativeLinksResolve`, checks that every relative link in the repository's Markdown resolves to a path in the repository, or to an issue, pull request or milestone at the depth that reaches the repository root. The backend documents' links to the Linux secretmem design now resolve.
- **build-and-release**: `make consumer-check` also runs `providertest.TestProvider` against the software provider from a scratch module outside the repository, so a published tag's `providertest` package is built and run the way a provider author's module uses it (#343).
- **build-and-release**: `make check-project-scripts`, run by `make lint-gates`, drives `swtpm-fixture.sh`, `test-runtimesecret.sh`, `cross-build.sh`, `lint-integration.sh` and `release-verify.sh` on stub tools on a temporary PATH (and a scratch git tree for `release-verify.sh`), checking each script's refusals, its exact calls on success, every failure it reports, and that `swtpm-fixture.sh` leaves no swtpm process or state directory (#349).
- **build-and-release**: `make check-it-runner`, part of `make lint-gates`, runs shell tests for the integration runner behind `make integration-test-<package>`, covering its usage refusals, `go test` and `covdata` failures, the coverage floor and a cover package missing from the profile.
- **build-and-release**: `make fuzz` fuzzes every native Go fuzz target in the root module and in each backend module for `FUZZTIME` each (default `30s`), with `FUZZ` and `FUZZ_PKG` selecting targets and packages, and stops at the first failure naming the package, the target and the failing input under `testdata/fuzz/`. `make check-fuzz-runner`, part of `make lint-gates`, drives it on a stub `go` (#351).

- **enclave-interface**: one contract test now covers every exported error type of the root package. `Error()` on zero and populated values carries the `enclave: ` prefix and never panics, `errors.Is` matches the type's own sentinels and no other, `errors.As` and `Unwrap` work through `%w` and `errors.Join`, and raw bytes in a caller-supplied name never reach a message verbatim; a completeness check fails on any exported error type or `Err...` sentinel added without a row (#345).

- **keyprotector-providers**: `backends/tpm` gains `FuzzParseBlob`, a native Go fuzz target that holds the sealed-blob parser to its contract on arbitrary input, with no TPM: it never panics or writes the blob, a refusal matches `ErrSealedAuthentication`, and an accepted blob is exactly the framing of its sealed-object public area and bounded private area (#336).
- **keyprotector-providers**: `backends/tpm`: malformed-response tables and the `FuzzExecuteResponse`, `FuzzCut2B` and `FuzzListType` fuzz targets, with seed corpora, for the TPM command-response path; a test proves the transport never hands the parser less than the response header (#346).
- **keyprotector-providers**: `backends/tpm` holds every error type and `Err...` sentinel to one contract table: the message carries the package prefix on zero and populated values, `errors.Is` matches only the type's own sentinels, `errors.As` finds the type through `%w` and `errors.Join`, `Unwrap` exposes the cause, and no byte field reaches a message; a source check fails on any exported error type or sentinel without a row (#371).
- **keyprotector-providers**: `docs/reference/` now carries the TCG standards the TPM provider implements: TPM 2.0 Library Parts 1–3 at revision 01.59 and the TCG EK Credential Profile 2.7, whose storage template shapes the provider's parent, each indexed with its sha256; `docs/sealing/hardware-providers.md` links them where it cites them (#335). Nothing changes for Go callers.

- **memory-enclave**: an integration test (`TestMemoryEnclave_ImportChangesNoProcessState`) proves a fresh process that links go-enclave but calls nothing in it stays dumpable, has nothing locked (`VmLck` 0), keeps the devcontainer's `RLIMIT_MEMLOCK`, and maps no `secretmem` area, all read back from the kernel.

- **provider-conformance**: `providertest` has runnable examples: `ExampleTestProvider` runs the conformance suite against the software provider with the `Config` fields the provider guide uses (`New`, `Modes`, `Logf`), and `ExampleTestProvider_invalidConfig` shows an empty `Config` refused with an error matching `ErrInvalidConfig` (#341).

- **public-release**: `make release-tree-check TAG=vX.Y.Z REF=<published ref>` checks, offline in the local clone, that the published commit's tree is byte-identical to the release tag's tree, and refuses naming both trees when they differ, when either does not resolve, or when the tag is not a release version (#332), and writes nothing.
- **public-release**: runnable examples on pkg.go.dev for the memory enclave, the locked-memory budget, backend detection and the shutdown sweep, linked from their user guides; `go test` runs them (#333). Documentation only; nothing changes for Go callers.

- **sealing**: Runnable examples `ExampleNewSealed`, `ExampleNewSealedFrom`, `ExampleSealed_OpenIn` and `ExampleNewSealer` show sealing, a late open inside the borrow window, an open into an explicit backend and a sealer over an explicit `KeyProtector`, and `go test` checks each against its output without printing material.
- **sealing**: Known-answer vectors for blob contract v1 in `testdata/contract-v1/` (SoftwareProvider blob, ModeRootKey KEK and DEK blobs, sealed values under envelope versions 1 and 2, and the blobs a reader must refuse) are rebuilt byte for byte by a standard-library reference encoder written from `docs/sealing/engineering.md` and opened through the package. A second implementer, such as a trusted application, can check its bytes against the same files.

### Fixed

- **arm-trustzone**: A trusted-application UUID with a dash in a hex-digit position is now refused with `*UUIDError` instead of being read with that dash skipped. ([#458](https://github.com/jeremyhahn/go-enclave/issues/458))

- **backend-conformance**: `backendtest.TestBackend` reports the residue property as `ErrNotMeasured` for material that is one repeated byte, such as a fresh zeroed region, instead of failing it (#367).
- **backend-conformance**: `backendtest.FindingsError` with no findings now returns `backendtest: no findings` from `Error()` instead of an empty string (#376). Messages with findings are unchanged.

- **build-and-release**: `scripts/cross-build.sh` with no target, or with no package, is now a usage error instead of passing (#349).
- **build-and-release**: `scripts/lint-integration.sh` with no package is now a usage error instead of passing (#349).
- **build-and-release**: The integration runner refuses a malformed coverage floor with exit status 2 before the suite runs, and accepts only `N` or `N.N`.
- **build-and-release**: Every integration runner usage refusal exits 2 in any POSIX sh, where a missing package, floor, `GO_ENCLAVE_IT_COVERPKG` or `GO_ENCLAVE_IT_TESTFLAGS` used to exit 1 when `sh` is bash.
- **build-and-release**: The feature-map gate no longer counts `docs/plans/` as a feature directory missing from `scripts/features.map` (#351).

- **keyprotector-providers**: `backends/tpm`: a response to an authorized command with bytes after its authorization area is now refused as malformed instead of accepted (#346).
- **keyprotector-providers**: `backends/tpm`: listing the device's handles takes each handle once, in ascending order, so a device that repeats a page can no longer list the same handle many times over (#346).
- **keyprotector-providers**: `backends/tpm`'s `DeviceError.Error` and `CommandError.Error` no longer panic when `Err` is nil (#371).

- **memory-enclave**: the residue sweep behind the `providertest` and `backendtest` residue checks now skips a thread-stack guard page (glibc on Linux 6.13 and later) instead of failing with an unreadable mapping, but only on a kernel whose `/proc/self/pagemap` reports `PM_GUARD_REGION` (Linux 6.15 or later, or a backport) and only when the process can read its pagemap. Elsewhere such a page, like every other unreadable page, still fails the sweep closed.

### Changed

- **BREAKING** backends: The nested module `github.com/jeremyhahn/go-enclave/backends/imxele` is removed; the i.MX EdgeLock Enclave holds keys only and moved to [go-xkms](https://github.com/jeremyhahn/go-xkms). See [Upgrading](docs/README.md#upgrading).

- **build-and-release**: update `golang.org/x/sys` to v0.50.0 in every module that requires it.
- **build-and-release**: CI (ci-template v1.35.3) and the code review (code-review v5.10.12) start when a draft pull request is marked ready (`ready_for_review`), so a PR leaves draft with a real gate and no empty commit; a buildgates test pins both triggers.

- **keyprotector-providers**: the secure-element provider's open questions 8-11 in [docs/sealing/hardware-providers.md](docs/sealing/hardware-providers.md#open-questions) carry proposed answers awaiting the owner's sign-off (#264): the provider proposed for go-xkms, not go-enclave, with a pure-Go PKCS#11 loader, SoftHSM as the CI fixture, a caller-supplied random GCM nonce with the usage limit left to the operator, and operator-provisioned keys with the user PIN handed in by the caller; nothing changes for Go callers.

- **public-release**: [Upgrading](docs/README.md#upgrading) covers v0.10.0-alpha, v0.11.0-alpha, v0.11.1-alpha and the next release, with the next release's Go 1.27.4 minimum and how to require the nested `backends/armtrustzone` and `backends/tpm` modules. Documentation only; nothing changes for Go callers.

[Unreleased]: https://github.com/jeremyhahn/go-enclave/compare/v0.12.0-alpha...HEAD
[v0.12.0-alpha]: https://github.com/jeremyhahn/go-enclave/compare/v0.11.1-alpha...v0.12.0-alpha

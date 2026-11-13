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

[Unreleased]: https://github.com/jeremyhahn/go-enclave/compare/v0.11.1-alpha...HEAD

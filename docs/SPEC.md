# go-enclave specification

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-11-12
> What the project is and every feature it has. [ROADMAP.md](../ROADMAP.md) carries what is complete and what remains; the two agree.
> A feature listed here, in any status, is never deleted: not its docs, code or issues. Removing or re-scoping one is a change to this file.

## Purpose

go-enclave is an enclave abstraction layer for Go, plus a software memory
enclave for hosts without enclave hardware. Callers consume one interface, the
handle plus its capabilities, and never a concrete type. `Detect` selects the
most secure backend the program registered. It is the base layer of its stack:
go-quicraft and every project above it consume and re-export this interface.

## Boundaries

go-enclave owns:

- **Locked-memory handling**: `mlock`, guard pages, canary, wipe on release
  ([ownership](memory-enclave/architecture.md#component-boundaries)).
- **Admission against a locked-memory budget**
  ([budget](locked-memory-budget/architecture.md#component-boundaries)).
- **The sealing envelope and the provider seam** (`KeyProtector`,
  `RootUnsealer`), with the memory provider `SoftwareProvider` in the root
  module and the TPM and TrustZone providers in nested modules
  ([sealing](sealing/architecture.md#component-boundaries)).
- **The backend seam**: the `Backend`, `Handle` and capability interfaces
  every backend implements, in this repository or out of tree
  ([backends](backends/architecture.md#component-boundaries)). Every
  environment a backend runs in must be attestable. A backend that produces
  evidence does so through `Attester`; the memory enclave, linux-secretmem and
  arm-trustzone produce none, and the host's platform attestation covers them.
- **The process-wide teardown**, `WipeAll`, which the consuming binary calls
  ([shutdown sweep](shutdown-sweep/architecture.md#component-boundaries)).
- **The conformance suites** it ships to provider and backend authors.
- **The enclave interface** as the SDK of the base layer ([purpose](#purpose)).

go-enclave never:

- **Takes process-wide lifecycle decisions.** `WipeAll` and `HardenProcess`
  are called by the program that owns the process, never by a library, which
  wipes only its own material with `Destroy`. Importing the package changes no
  process state.
- **Purges on failure.** A failed allocation fails that allocation with a
  typed error and never touches another enclave.
- **Adds a dependency to the root module.** The root module requires only
  `golang.org/x/sys`. Device code that needs more lives in a nested module
  (`backends/tpm`, `backends/armtrustzone`) or out of tree, which requires the
  root and never the reverse.
- **Performs key operations on a device.** A TPM or secure element enters
  go-enclave only as a `KeyProtector` provider that wraps data keys; signing
  and decryption on those devices belong to a KMS such as go-xkms.
- **Persists or transports material.** No persistence or transport format, no
  cross-process sharing.
- **Is a database, cluster, engine, store, service or network client.**
- **Destroys automatically.** No finalizer, fault handler or garbage
  collection of enclaves; nothing is destroyed except by its owner's
  `Destroy` or an explicit `WipeAll`.
- **Parses or appraises attestation evidence**; it carries it as `Evidence`.
- **Supports boringcrypto builds** for sealing.
- **Builds where it cannot lock memory**: an unsupported GOOS fails to compile.
- **Names types for their contents**: no `Secret`, `SecureString`,
  `SecureBytes` or `ProtectedBuffer`.

## Features

| Feature | Status | Requirements | Detail |
|---|---|---|---|
| memory-enclave | shipped | The default software backend. The memory enclave (a `ByteAccess` from `NewMemory`, `NewMemoryCopy` or `NewMemorySized`) keeps material in `mlock`'d pages between guard pages with a canary, out of core dumps and `fork` children where the OS allows, read only through the `WithBytes` borrow, read-only after `Freeze` through the `Freezer` capability, and wiped before release. Every failure is a typed error that touches no other enclave. Opt-in `HardenProcess`. Compiles on every GOOS in the [platform contract](memory-enclave/engineering.md#platform-contract). | [memory-enclave/](memory-enclave/user.md) |
| locked-memory-budget | shipped | `Allocator` admits against a budget in page-rounded locked bytes before allocating, by compare-and-swap; refunds failed constructions; discovers `RLIMIT_MEMLOCK`; retunes at runtime; one process allocator installed by the binary and drawn on by libraries. | [locked-memory-budget/](locked-memory-budget/user.md) |
| sealing | shipped | `Sealed` holds a versioned AES-256-GCM envelope at rest and decrypts only into a fresh, frozen memory enclave on `Open`. `Sealer` (from `NewSealer`) has modes `ModeRootKey` and `ModePerOperation`, selected by the typed `KeyProtector` / `RootUnsealer` options; provider calls take a context. Works under FIPS 140-only mode; opt-in strict key-schedule erasure. | [sealing/](sealing/user.md) |
| keyprotector-providers | in progress | Providers behind the `KeyProtector` seam, each meeting [blob contract v1](sealing/engineering.md#blob-contract-v1). **Memory** (`SoftwareProvider`) and **TPM** (`backends/tpm`, TPM 2.0 sealed-data objects, passing `providertest` on swtpm) ship. **TrustZone** (`(*armtrustzone.Backend).KeyProtector`) ships on the host side; the OP-TEE trusted application's SEAL and UNSEAL commands are not in the pinned trusted-firmware release yet. **Secure element** (PKCS#11) waits on [open questions 8-11](sealing/hardware-providers.md#open-questions). Named consumers: go-xkms's `EnclaveBackend` and trusted-firmware's trusted application. [#264](../../../issues/264). | [sealing/](sealing/hardware-providers.md) |
| shutdown-sweep | shipped | `WipeAll(ctx)` reclaims every live enclave and orphaned mapping, never unmapping one a reader holds, waiting only as long as `ctx` allows, then sweeps registered `Sweeper` backends; findings are one typed `*SweepError`. | [shutdown-sweep/](shutdown-sweep/user.md) |
| provider-conformance | shipped | `providertest.TestProvider(ctx, cfg)` checks that a provider retains nothing, refuses tampered and forged blobs, honors its context and implements only the modes it claims; it fails closed where it cannot measure. | [provider-conformance/](provider-conformance/user.md) |
| backends | shipped | A small core (`Handle`, `Backend`) plus optional capabilities found by type assertion; a named registry beside explicit injection, with nothing registered at import; a missing capability is a `*CapabilityError`, never a fallback. Sealing opens into and seals from any backend. | [backends/](backends/user.md) |
| backend-conformance | shipped | `backendtest.TestBackend(ctx, cfg)` holds a backend to the seam: handle lifecycle, exact capability claims in both directions, import wiping, nonce binding through the author's `VerifyEvidence`; it fails closed. | [backend-conformance/](backend-conformance/user.md) |
| build-and-release | shipped | Every gate is a Makefile target that passes offline in the devcontainer, with pinned, checksum-verified tools. A change callers can see adds a changelog fragment. `make release`, `make release-candidate` and `make release-alpha` each cut one kind of release from `main`; the tag's workflow runs the full gate (FIPS and trivy included) and a consumer check, and the commit and tag are signed. [build and release](build-and-release.md). | none |
| enclave-interface | shipped | The one public interface callers consume: the handle plus capabilities. Constructors return it; concrete types are backend-internal. [#138](../../../issues/138). | none |
| backend-detection | shipped | `Detect` runs only on an explicit call from `main`, over only the backends the binary registered; probing the host is each backend's own code. Each backend reports its rank, and go-enclave fixes no ranking of its own. It selects the most secure usable backend, the memory enclave when nothing else is usable, and reports why each other was passed over. [#190](../../../issues/190). | [backend-detection/](backend-detection/user.md) |
| public-release | in progress | The first public release is a plain `vX.Y.Z` tag cut from `main` with `make release`, after a release candidate has passed its tag workflow and staging. The published tree is the tag's tree and names no private host (`make check-releasability`). From that release on, a breaking change ships with its migration in [Upgrading](README.md#upgrading). | [build and release](build-and-release.md) |
| linux-secretmem | shipped | A Linux-only software backend (`NewSecretMemory`) holding material in `memfd_secret(2)` memory, which is locked, out of core dumps and the kernel direct map, and refuses `/proc/<pid>/mem`, `process_vm_readv` and other GUP access. It passes `backendtest` and reports rank 1, above the memory enclave and below every hardware backend. On a host that refuses `memfd_secret` (`ENOSYS`, `EPERM`, `ENOMEM`) detection keeps the memory enclave and reports why. Off Linux it is a build-only stub. [#261](../../../issues/261). | [linux-secretmem/](linux-secretmem/user.md) |
| open-in-secretmem | shipped | `Sealed.OpenIn` into a linux-secretmem backend decrypts straight into the new handle's `memfd_secret(2)` pages, admitted against that backend's budget first: no scratch enclave, import or heap buffer holds the plaintext. A tampered value is refused with `ErrSealedAuthentication` and a cancelled context with `ErrOpenFailed`. A refused `memfd_secret` fails the open; it never falls back to a weaker destination. [#263](../../../issues/263). | [linux-secretmem/](linux-secretmem/user.md) |
| mac-secure-enclave | future | A backend on the Mac Secure Enclave that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). [#192](../../../issues/192). | [backends/](backends/user.md) |
| arm-trustzone | shipped | A backend over OP-TEE, the secure world of Arm TrustZone: the nested module `backends/armtrustzone`, pure Go over the Linux TEE driver (`/dev/tee0`) with the GlobalPlatform TEE Client API's semantics. It probes trusted-firmware's trusted application and fills memory enclave handles from its random-number command, at rank 2. It passes `backendtest` on an OP-TEE fixture (`make integration-test-arm-trustzone`). [Design](backends/arm-trustzone-design.md), [engineering](backends/engineering.md#arm-trustzone). [#206](../../../issues/206). | [backends/](backends/user.md#arm-trustzone) |
| intel-sgx | future | A backend on Intel SGX that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). [#193](../../../issues/193). | [backends/](backends/user.md) |
| amd-sev | future | A backend on AMD SEV-SNP that implements the backend seam and passes `backendtest`. [Proposal](backends/amd-sev.md). [#194](../../../issues/194). | [backends/](backends/user.md) |
| imx-edgelock-enclave | future | A backend on the NXP i.MX 95 EdgeLock Secure Enclave that implements the backend seam and passes `backendtest`. The secure-world firmware it binds to lives outside go-enclave; nothing device-specific is implemented here. Consumed by go-xkms. [Proposal](backends/imx-edgelock-enclave.md). [#195](../../../issues/195). | [backends/](backends/user.md) |
| intel-tdx | future | A backend on Intel TDX that implements the backend seam and passes `backendtest`. [Proposal](backends/intel-tdx.md). [#199](../../../issues/199). | [backends/](backends/user.md) |
| nvidia-blackwell | future | A backend on NVIDIA Blackwell confidential computing that implements the backend seam and passes `backendtest`. [Proposal](backends/nvidia-blackwell.md). [#200](../../../issues/200). | [backends/](backends/user.md) |

## Interfaces

- **SDK**: the Go package `github.com/jeremyhahn/go-enclave` (package
  `enclave`); [documentation index](README.md), API reference on
  [pkg.go.dev](https://pkg.go.dev/github.com/jeremyhahn/go-enclave).
- **SDK, nested modules**: `backends/tpm` (package `tpm`) and
  `backends/armtrustzone` (package `armtrustzone`), each its own Go module.
- **SDK, provider authors**: `providertest`;
  [provider-conformance](provider-conformance/api.md).
- **SDK, backend authors**: `backendtest`;
  [backend-conformance](backend-conformance/api.md).
- **CLI**: none; this is a library.
- **API transport**: none; callers reach it only through the exported Go API.

## Release criteria

The next release is the first public release (public-release). It is cut
when:

1. Every feature marked shipped holds on `main`. The future backends are not
   part of it.
2. Every change since the last release passed CI and one review.
3. CI runs build, unit, integration, security and dependency checks
   (`make build`, `make test`, `make integration-test`, `make security`,
   `make deps-check`), all in the project devcontainer image.
4. Every module's dependencies are at their latest release (`make deps-check`).
5. `make check-releasability` passes on `main`: no tracked file names a
   private host, address or workstation path.
6. A release candidate is cut from `main` with
   `make release-candidate VERSION=vX.Y.Z-rc.N`, its tag's release workflow
   passes (`make release-verify`, the full gate with FIPS and trivy, and
   `make consumer-check`), and it stays one week in staging with every
   integration suite green.
7. A maintainer confirms the version, and `make release VERSION=vX.Y.Z` cuts
   it from `main`; its tag's release workflow passes.
8. The release is published to GitHub as one commit whose tree is
   byte-identical to the tag's tree.

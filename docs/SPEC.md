# go-enclave specification

> **Status: NORMATIVE** · Scope: go-enclave · Owner: Software Department · Last verified: 2026-10-26
> What the project is and every feature it has. [ROADMAP.md](../ROADMAP.md) carries what is complete and what remains; the two agree.
> A feature listed here, in any status, is never deleted: not its docs, code or issues; only the owner removes or re-scopes one, by changing this file.

## Purpose

go-enclave is the enclave abstraction layer plus the default software memory
enclave for hosts without hardware. Upstream projects consume one clearly
defined interface and never a concrete implementation or a pointer to one.
go-enclave detects the most secure backend present and hands upstream that
one; backends to come are the Mac Secure Enclave, Arm TrustZone on OP-TEE,
Intel SGX, AMD SEV and any other hardware or software enclave.
Today the memory enclave is the only backend. It is a Layer 0 Go library with
one dependency, `golang.org/x/sys`.

Its layer is the base of the stack, under go-quicraft and every project above
it. It embeds no in-house project as a library, so it inherits nothing and
re-exports nothing. Its SDK is the enclave interface (enclave-interface). Each
layer above takes that interface in and re-exports it through its own SDK; none
wraps it or re-models it under its own name.

One cluster engine and one datastore serve each deployment, and they are
go-qrdb's. go-enclave is no cluster engine, database or datastore, and holds no
store, service or client of its own.

## Boundaries

go-enclave owns:

- **Locked-memory handling for the portfolio**: `mlock`, guard pages, canary,
  wipe on release. No other project carries its own
  ([ownership](memory-enclave/architecture.md#component-boundaries)).
- **Admission against a locked-memory budget**; no other project hand-rolls one
  ([budget](locked-memory-budget/architecture.md#component-boundaries)).
- **The sealing envelope and the provider seam** (`KeyProtector`,
  `RootUnsealer`), with one shipped provider, `SoftwareProvider`
  ([sealing](sealing/architecture.md#component-boundaries)); the planned
  providers (memory, TrustZone, secure element, TPM) and the named consumers
  (go-xkms's `EnclaveBackend`, trusted-firmware) are the
  [keyprotector-providers](#features) row.
- **The backend seam**: the `Backend`, `Handle` and capability interfaces that
  hardware backend modules implement
  ([backends](backends/architecture.md#component-boundaries)). Every
  environment must be attestable: the requirement binds every backend, in
  this module and out of tree. Hardware backends attest through `Attester`;
  the memory enclave does not attest itself, and its environment is attested
  through the host's platform attestation, which go-xkms and
  go-trusted-platform own.
- **The process-wide teardown**, `WipeAll`, which the consuming binary calls
  ([shutdown sweep](shutdown-sweep/architecture.md#component-boundaries)).
- **The conformance suites** it ships to provider and backend authors.
- **The enclave interface** as the SDK of the base layer, which every layer
  above re-exports ([purpose](#purpose)).

go-enclave never:

- **Takes process-wide lifecycle decisions.** `WipeAll` and `HardenProcess`
  are called by the program that owns the process, never by a library, which
  wipes only its own material with `Destroy`. Importing the package changes no
  process state.
- **Purges on failure.** A failed allocation fails that allocation with a
  typed error and never touches another enclave.
- **Carries hardware code.** No hardware backend, hardware-specific code or
  second dependency in this module: hardware backends live in their own
  modules. The TPM backend, and TPM, PKCS#11 and cloud KMS crypto, belong to
  go-xkms.
- **Persists or transports material.** No persistence or transport format, no
  cross-process sharing.
- **Is a database, cluster, engine, store, service or network client**
  ([purpose](#purpose)).
- **Imports an in-house project.** Each layer above imports go-enclave and
  re-exports its interface; none carries a second copy of it.
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
| memory-enclave | shipped | The default software backend. The memory enclave (a `ByteAccess` from `NewMemory`, `NewMemoryCopy` or `NewMemorySized`) keeps material in `mlock`'d pages between guard pages with a canary, out of core dumps and `fork` children where the OS allows, read only through the `WithBytes` borrow, read-only after `Freeze` through the `Freezer` capability, and wiped before release. Every failure is a typed error that touches no other enclave. Opt-in `HardenProcess`. Compiles on every GOOS in the [platform contract](memory-enclave/engineering.md#platform-contract). [Architecture](memory-enclave/architecture.md). | [memory-enclave/](memory-enclave/user.md) |
| locked-memory-budget | shipped | `Allocator` admits against a budget in page-rounded locked bytes before allocating, by compare-and-swap; refunds failed constructions; discovers `RLIMIT_MEMLOCK`; retunes at runtime; one process allocator installed by the binary and drawn on by libraries. [Architecture](locked-memory-budget/architecture.md). | [locked-memory-budget/](locked-memory-budget/user.md) |
| sealing | shipped | `Sealed` holds an AES-256-GCM envelope at rest and decrypts only into a fresh, frozen memory enclave (a `ByteAccess`) on `Open`. `Sealer`, an interface (`NewSealer` returns `Sealer`), has modes `ModeRootKey` and `ModePerOperation`, selected by the typed `KeyProtector` / `RootUnsealer` options; provider calls take a context. Works under FIPS 140-only mode; opt-in strict key-schedule erasure. [Architecture](sealing/architecture.md). | [sealing/](sealing/user.md) |
| keyprotector-providers | planned | go-enclave owns the protected-memory primitives, the secure- and insecure-world handling, the sealing envelope and the `KeyProtector` provider seam. Four providers sit behind that seam: **memory**, today's `SoftwareProvider`, used when no hardware is present; **TrustZone**, the OP-TEE TA, where trusted-firmware implements SEAL (command 0x3) and UNSEAL (command 0x4) against go-enclave's blob contract; **secure element**; and **TPM**. Two consumers are named: go-xkms's `EnclaveBackend`, a go-xkms crypto `Backend` whose key material rests in go-enclave `Sealed` envelopes and which selects any go-enclave backend by configuration; and trusted-firmware, whose TA implements the blob contract. Ruled (225(3), owner item 170): go-enclave owns the seam; TPM and secure element enter go-enclave only as `KeyProtector` providers, and go-xkms's TPM and PKCS#11 crypto backends stay key-operation backends. The blob contract is [contract v1](sealing/engineering.md#blob-contract-v1). [#264](../../../issues/264). | [sealing/](sealing/user.md) |
| shutdown-sweep | shipped | `WipeAll(ctx)` reclaims every live enclave and orphaned mapping, never unmapping one a reader holds, waiting only as long as `ctx` allows, then sweeps registered `Sweeper` backends; findings are one typed `*SweepError`. [Architecture](shutdown-sweep/architecture.md). | [shutdown-sweep/](shutdown-sweep/user.md) |
| provider-conformance | shipped | `providertest.TestProvider(ctx, cfg)` checks that a provider retains nothing, refuses tampered and forged blobs, honors its context and implements only the modes it claims; it fails closed where it cannot measure. [Architecture](provider-conformance/architecture.md). | [provider-conformance/](provider-conformance/user.md) |
| backends | shipped | A small core (`Handle`, `Backend`) plus optional capabilities found by type assertion; a named registry beside explicit injection, with nothing registered at import; a missing capability is a `*CapabilityError`, never a fallback. Sealing opens into and seals from any backend. [Architecture](backends/architecture.md). | [backends/](backends/user.md) |
| backend-conformance | shipped | `backendtest.TestBackend(ctx, cfg)` holds a backend to the seam: handle lifecycle, exact capability claims in both directions, import wiping, nonce binding through the author's `VerifyEvidence`; it fails closed. [Architecture](backend-conformance/architecture.md). | [backend-conformance/](backend-conformance/user.md) |
| build-and-release | shipped | Every gate is a Makefile target that passes offline in the devcontainer, with pinned, checksum-verified tools. A change adds a changelog fragment. `make release`, `make release-candidate` and `make release-alpha` each cut one kind of release from `main`; the tag's workflow runs the full gate (FIPS and trivy included) and a consumer check, and the artifacts are signed. [build and release](build-and-release.md). | none |
| enclave-interface | shipped | The one public interface upstream consumes: the handle plus capabilities. Constructors return it; concrete types are backend-internal. No upstream project depends on a concrete type. [#138](../../../issues/138), milestone v0.9.0 dev complete. | none |
| backend-detection | shipped | Detection runs only on an explicit call from `main`; importing the package changes no process state. It covers only the backends the binary registered, and probing the host is each backend's own code. Each backend reports its rank; go-enclave compares the ranks and fixes no ranking of its own. It selects the most secure usable backend, the memory enclave when nothing else is usable; the selection is observable and testable. [#190](../../../issues/190), milestone v0.9.0 dev complete. [Architecture](backend-detection/architecture.md). | [backend-detection/](backend-detection/user.md) |
| public-release | in progress | The first public release is a plain `vX.Y.Z` tag cut from `main` with `make release`, its version confirmed at the owner's publish approval, after a release candidate has passed its tag workflow and staging. The published tree is the tag's tree, which names no lab host and carries no agent-only file (`make check-releasability`). From that release on, a breaking change ships with its migration in [Upgrading](README.md#upgrading). | [build and release](build-and-release.md) |
| linux-secretmem | shipped | A Linux-only software backend holding material in `memfd_secret(2)` memory, which is locked, out of core dumps and the kernel direct map, and refuses `/proc/<pid>/mem`, `process_vm_readv` and other GUP access. It implements the backend seam and passes `backendtest`. It reports a rank above the memory enclave's and below every hardware backend's. Its probe runs only from the explicit detection call and succeeds only where `memfd_secret` is usable; on a host that refuses it (`ENOSYS`, `EPERM`, `ENOMEM`) detection keeps the memory enclave selected and reports why. Off Linux it is a build-only stub per the [platform contract](memory-enclave/engineering.md#platform-contract). [#253](../../../issues/253), [#261](../../../issues/261). [Architecture](linux-secretmem/architecture.md). | [linux-secretmem/](linux-secretmem/user.md) |
| open-in-secretmem | shipped | `Sealed.OpenIn` into a linux-secretmem backend decrypts straight into the new handle's `memfd_secret(2)` pages, admitted against that backend's budget before anything is decrypted: no locked-memory scratch enclave, import or heap buffer ever holds the plaintext. A tampered or forged value is refused with `ErrSealedAuthentication` and a cancelled context with `ErrOpenFailed`, each allocating nothing that outlives the call. A refused `memfd_secret` fails the open typed; it never falls back to a weaker destination. Every other backend opens as before. [#263](../../../issues/263). [Architecture](linux-secretmem/architecture.md). | [linux-secretmem/](linux-secretmem/user.md) |
| mac-secure-enclave | future | A backend on the Mac Secure Enclave that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). [#192](../../../issues/192). | [backends/](backends/user.md) |
| arm-trustzone | future | A host-side backend over the GlobalPlatform TEE Client API, on OP-TEE, that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). trusted-firmware owns the OP-TEE secure world it binds to; blocked until trusted-firmware's OP-TEE row lands. The seam the `backendtest` harness assumes: the registered backend has `Connect(endpoint string) (enclave.Backend, error)`, the connected one `Random(ctx, n) (enclave.Handle, error)`, and under the `optee` build tag the backend supplies `test/integration/enclave/arm_trustzone_register_test.go`, which registers it in the test process with `enclave.Register` under `arm-trustzone` ([harness](backend-conformance/engineering.md#the-arm-trustzone-harness)). [#206](../../../issues/206). | [backends/](backends/user.md) |
| intel-sgx | future | A backend on Intel SGX that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). [#193](../../../issues/193). | [backends/](backends/user.md) |
| amd-sev | future | A backend on AMD SEV that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). [#194](../../../issues/194). | [backends/](backends/user.md) |
| imx-edgelock-enclave | future | A go-enclave backend that binds the Linux side (xkmsd) to the trusted-imx95 secure world through that repo's interface, consumed by go-xkms's `hsm-appliance` feature. The secure world and the secure key handling code live in trusted-imx95; nothing device-specific is implemented in go-enclave. [#195](../../../issues/195). | [backends/](backends/user.md) |
| intel-tdx | future | A backend on Intel TDX that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). [#199](../../../issues/199). | [backends/](backends/user.md) |
| nvidia-blackwell | future | A backend on NVIDIA Blackwell confidential computing that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). [#200](../../../issues/200). | [backends/](backends/user.md) |

## Interfaces

- **SDK**: the Go package `github.com/jeremyhahn/go-enclave` (package
  `enclave`); [documentation index](README.md), API reference on
  [pkg.go.dev](https://pkg.go.dev/github.com/jeremyhahn/go-enclave).
- **SDK, provider authors**: `providertest`;
  [provider-conformance](provider-conformance/api.md).
- **SDK, backend authors**: `backendtest`;
  [backend-conformance](backend-conformance/api.md).
- **CLI**: none; this is a library ([index](README.md)).
- **API transport**: none; consumers reach it only through the exported Go API
  ([ownership](memory-enclave/architecture.md#component-boundaries)).

## Release criteria

The next release is the first public release (public-release). It is cut
when:

1. Every feature marked shipped holds on `main`. The future backends are not
   part of it; each ships in a later release.
2. Every change since the last release passed CI and one review.
3. CI conforms to the handbook's CI standard,
   `software/conventions/ci-standard.md`:
   build, unit, integration, security and the latest-version check
   (`make build`, `make test`, `make integration-test`, `make security`,
   `make deps-check`), all in the project devcontainer image.
4. The module has no in-house upstream; its one dependency,
   `golang.org/x/sys`, is at its latest version (`make deps-check`).
5. `make check-releasability` passes on `main`: no tracked file names the lab
   fleet or is agent-only.
6. A release candidate is cut from `main` with
   `make release-candidate VERSION=vX.Y.Z-rc.N`, its tag's release workflow
   passes (`make release-verify`, the full gate with FIPS and trivy, and
   `make consumer-check`), and it exits staging after one week with every P1
   integration suite green.
7. The version is confirmed at the owner's publish approval, and
   `make release VERSION=vX.Y.Z` cuts it from `main`; its tag's release
   workflow passes.
8. The release is published to GitHub as one commit whose tree is
   byte-identical to the tag's tree.

# go-enclave specification

> **Status: NORMATIVE** · Scope: go-enclave · Owner: Software Department
> What the project is and every feature it has. [ROADMAP.md](../ROADMAP.md) carries what is complete and what remains; the two agree.
> A feature listed here, in any status, is never deleted: not its docs, code or issues; only the owner removes or re-scopes one, by changing this file.

## Purpose

go-enclave is the enclave abstraction layer plus the default software memory
enclave for hosts without hardware. Upstream projects consume one clearly
defined interface and never a concrete implementation or a pointer to one.
go-enclave detects the most secure backend present and hands upstream that
one; backends to come are secure elements such as the EdgeLock SE052F, the Mac
Secure Enclave, Intel SGX, AMD SEV and any other hardware or software enclave.
Today the memory enclave is the only backend. It is a Layer 0 Go library with
one dependency, `golang.org/x/sys`.

## Boundaries

go-enclave owns:

- **Locked-memory handling for the portfolio**: `mlock`, guard pages, canary,
  wipe on release. No other project carries its own
  ([ownership](locked-memory/architecture.md#component-boundaries)).
- **Admission against a locked-memory budget**; no other project hand-rolls one
  ([budget](locked-memory-budget/architecture.md#component-boundaries)).
- **The sealing envelope and the provider seam** (`KeyProtector`,
  `RootUnsealer`), with one shipped provider, `SoftwareProvider`
  ([sealing](sealing/architecture.md#component-boundaries)).
- **The backend seam**: the `Backend`, `Handle` and capability interfaces that
  hardware backend modules implement
  ([backends](backends/architecture.md#component-boundaries)).
- **The process-wide teardown**, `WipeAll`, which the consuming binary calls
  ([shutdown sweep](shutdown-sweep/architecture.md#component-boundaries)).
- **The conformance suites** it ships to provider and backend authors.

go-enclave never:

- **Takes process-wide lifecycle decisions.** `WipeAll` and `HardenProcess`
  are called by the program that owns the process, never by a library, which
  wipes only its own material with `Destroy`. Importing the package changes no
  process state.
- **Purges on failure.** A failed allocation fails that allocation with a
  typed error and never touches another enclave.
- **Carries hardware code.** No hardware backend, hardware-specific code or
  second dependency in this module: hardware backends live in their own
  modules, and TPM, PKCS#11 and cloud KMS crypto belongs to go-xkms.
- **Persists or transports material.** No persistence or transport format, no
  cross-process sharing.
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
| memory-enclave | shipped | The default software backend. `Memory` keeps material in `mlock`'d pages between guard pages with a canary, out of core dumps and `fork` children where the OS allows, read only through the `WithBytes` borrow, read-only after `Freeze`, and wiped before release. Every failure is a typed error that touches no other enclave. Opt-in `HardenProcess`. Compiles on every GOOS in the [platform contract](locked-memory/engineering.md#platform-contract). [Architecture](locked-memory/architecture.md). | [locked-memory/](locked-memory/user.md) |
| locked-memory-budget | shipped | `Allocator` admits against a budget in page-rounded locked bytes before allocating, by compare-and-swap; refunds failed constructions; discovers `RLIMIT_MEMLOCK`; retunes at runtime; one process allocator installed by the binary and drawn on by libraries. [Architecture](locked-memory-budget/architecture.md). | [locked-memory-budget/](locked-memory-budget/user.md) |
| sealing | shipped | `Sealed` holds an AES-256-GCM envelope at rest and decrypts only into a fresh, frozen `Memory` on `Open`. `Sealer` modes `ModeRootKey` and `ModePerOperation`, selected by the typed `KeyProtector` / `RootUnsealer` options; provider calls take a context. Works under FIPS 140-only mode; opt-in strict key-schedule erasure. [Architecture](sealing/architecture.md). | [sealing/](sealing/user.md) |
| shutdown-sweep | shipped | `WipeAll(ctx)` reclaims every live enclave and orphaned mapping, never unmapping one a reader holds, waiting only as long as `ctx` allows, then sweeps registered `Sweeper` backends; findings are one typed `*SweepError`. [Architecture](shutdown-sweep/architecture.md). | [shutdown-sweep/](shutdown-sweep/user.md) |
| provider-conformance | shipped | `providertest.TestProvider(ctx, cfg)` checks that a provider retains nothing, refuses tampered and forged blobs, honors its context and implements only the modes it claims; it fails closed where it cannot measure. [Architecture](provider-conformance/architecture.md). | [provider-conformance/](provider-conformance/user.md) |
| backends | shipped | A small core (`Handle`, `Backend`) plus optional capabilities found by type assertion; a named registry beside explicit injection, with nothing registered at import; a missing capability is a `*CapabilityError`, never a fallback. Sealing opens into and seals from any backend. [Architecture](backends/architecture.md). | [backends/](backends/user.md) |
| backend-conformance | shipped | `backendtest.TestBackend(ctx, cfg)` holds a backend to the seam: handle lifecycle, exact capability claims in both directions, import wiping, nonce binding through the author's `VerifyEvidence`; it fails closed. [Architecture](backend-conformance/architecture.md). | [backend-conformance/](backend-conformance/user.md) |
| build and release | shipped | Every gate is a Makefile target that passes offline in the devcontainer, with pinned, checksum-verified tools. A change adds a changelog fragment. `make release`, `make release-candidate` and `make release-alpha` each cut one kind of release from `main`; the tag's workflow runs the full gate (FIPS and trivy included) and a consumer check, and the artifacts are signed. [Development](../README.md#development). | none |
| enclave-interface | in progress | The one public interface upstream consumes: the handle plus capabilities. Constructors return it; concrete types are backend-internal. No upstream project depends on a concrete type. [#138](../../../issues/138), milestone v0.9.0-rc.1. | none |
| backend-detection | planned | At start go-enclave probes the host and selects the most secure backend present, the memory enclave when nothing else; the selection is observable and testable. [#190](../../../issues/190), milestone v0.9.0-rc.1. | none |
| BSD and Windows runtime testing | planned | The BSDs and Windows run the test suite, not only compile; until then they are build-only ([test status](locked-memory/engineering.md#test-status)). [#188](../../../issues/188), milestone v0.9.0-rc.1. | none |
| se052f-secure-element | future | A backend on the EdgeLock SE052F secure element that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). It is the host-side Go backend; trusted-firmware owns the on-device C driver for the same part as its element tier. [#191](../../../issues/191). | [backends/](backends/user.md) |
| optiga-trust-m | future | A backend on the Infineon OPTIGA Trust M I2C element that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). It is the host-side Go backend; trusted-firmware owns the on-device driver for the same part. [#196](../../../issues/196). | [backends/](backends/user.md) |
| mac-secure-enclave | future | A backend on the Mac Secure Enclave that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). [#192](../../../issues/192). | [backends/](backends/user.md) |
| intel-sgx | future | A backend on Intel SGX that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). [#193](../../../issues/193). | [backends/](backends/user.md) |
| amd-sev | future | A backend on AMD SEV that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). [#194](../../../issues/194). | [backends/](backends/user.md) |
| imx-edgelock-enclave | future | A go-enclave backend that binds the Linux side (xkmsd) to the trusted-imx95 secure world through that repo's interface, consumed by go-xkms's `hsm-appliance` feature. The secure world and the secure key handling code live in trusted-imx95; nothing device-specific is implemented in go-enclave. [#195](../../../issues/195). | [backends/](backends/user.md) |
| intel-tdx | future | A backend on Intel TDX that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). | [backends/](backends/user.md) |
| tpm | future | A backend on a TPM that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). | [backends/](backends/user.md) |
| nvidia-blackwell | future | A backend on NVIDIA Blackwell confidential computing that implements the backend seam and passes `backendtest` ([out-of-tree backend](backends/architecture.md#an-out-of-tree-backend)). | [backends/](backends/user.md) |

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
  ([ownership](locked-memory/architecture.md#component-boundaries)).

## Release criteria

The next candidate, [v0.9.0-rc.1](../../../milestone/34) (see
[ROADMAP milestones](../ROADMAP.md#milestones)), closes when:

1. The enclave interface is the public API (enclave-interface).
2. Detection selects the memory backend on a plain host (backend-detection).
3. Every issue in the milestone is closed.
4. `make release-candidate` passes on `main`.
5. The candidate is cut from `main` with
   `make release-candidate VERSION=v0.9.0-rc.1` and published as a
   pre-release.
6. The tag's release workflow passes: `make release-verify`, the full gate
   (FIPS and trivy included) and `make consumer-check`.
7. The version is confirmed at the owner's publish approval.

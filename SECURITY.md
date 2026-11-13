# Security policy

go-enclave holds key material in locked memory and seals it at rest. A defect
here is a security defect for everything built on it, so reports are welcome
and handled privately.

## Supported versions

go-enclave is pre-1.0. Only the **latest release** receives security fixes:
the newest tag (`vX.Y.Z-alpha`, `vX.Y.Z-rc.N`), or the newest `vX.Y.Z` once
final releases exist. Fixes ship as a new version and are not backported to an
older minor. While the module is pre-1.0, breaking changes land in a MINOR
bump, so upgrading to get a fix can require the steps in
[Upgrading](docs/README.md#upgrading).

| Version | Supported |
|---|---|
| Latest release | Yes |
| Anything older | No, upgrade |

This covers the root module and the two modules in this repository under
`backends/`: the TPM provider (`backends/tpm`) and the arm-trustzone backend
and provider (`backends/armtrustzone`). Reports against the BSDs and Windows
are in scope, though they are build-only
([test status](docs/memory-enclave/engineering.md#test-status)).

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a suspected
vulnerability.**

Report it privately through GitHub's private vulnerability reporting:

**<https://github.com/jeremyhahn/go-enclave/security/advisories/new>**

This is the repository's **Security** tab, then **Report a vulnerability**.

Please include:

- the go-enclave version (tag or commit), the module (root, `backends/tpm` or
  `backends/armtrustzone`), Go version, GOOS/GOARCH, and whether FIPS mode
  (`GOFIPS140`, `GODEBUG=fips140=only`) was in use;
- the affected API, the sealing mode (`ModeRootKey` or `ModePerOperation`) and
  the provider or backend, if any;
- a minimal reproduction or proof of concept, and what an attacker gains;
- whether you believe it is already being exploited.

## Scope

In scope:

- **Memory exposure.** Key material or plaintext reaching swap, the ordinary
  heap (beyond the documented key-schedule exposure), or another process;
  material surviving `Destroy` or `WipeAll`; unmapping or reading memory under
  a live borrow.
- **Residue.** Copies of material left in this process after the API says
  they are gone, including in `providertest`'s own instruments.
- **Core-dump leaks.** Enclave pages reaching a core dump on a platform where
  this package claims a per-mapping exclusion, or `CoreDumpsDisabled`
  reporting a protection that is not in force.
- **Cryptographic misuse.** A GCM key used past its documented message limit
  (or any nonce reuse that limit does not account for), unauthenticated or
  re-pairable envelopes, oracles in error reporting, non-approved cryptography
  on a sealing path.
- **Provider-contract violations by this package.** Calling `UnsealRoot` more
  than once after it succeeded; holding a `Sealer` or `Sealed` mutex across a
  provider call (the init semaphore, and the borrow of the private per-call
  enclave the provider writes into, span `UnsealRoot` by design); silent
  re-keying after a sweep; a conformance-suite check that can pass a provider
  or backend that violates the contract.
- **The in-repo hardware modules.** The TPM provider (`backends/tpm`) and the
  arm-trustzone backend and provider (`backends/armtrustzone`): key material
  left outside locked memory, a blob accepted after tampering or under another
  parent, or a device response that is trusted without being checked.
- **Admission-control bypass.** Admitting allocations past an `Allocator`
  budget beyond what its documentation allows (the over-subscription
  `ForceLimit` reports, and `OpenIn`'s unadmitted transient key pages), or one
  failure destroying another caller's enclave.
- **Build and release supply chain.** The Makefile, pinned tool installation
  and checksum verification, `scripts/`, and the CI and release workflows,
  for example a tag or input that executes as code, or a release published
  from an ungated commit.

Out of scope, because these are documented limits and not vulnerabilities.
A report that shows the documentation understates one is in scope.

- An adversary who can read this process's live memory (`ptrace`,
  `/proc/<pid>/mem`, a debugger): a memory enclave is readable for its whole
  life, and with the software provider or `ModeRootKey` the sealing keys are
  too. A linux-secretmem handle is the exception: the kernel refuses its pages
  to `ptrace` and `/proc/<pid>/mem`.
- AES key schedules left on the heap by seals and opens, as described in
  [docs/sealing/engineering.md](docs/sealing/engineering.md#key-schedule-heap-exposure),
  in builds where `KeyScheduleErasure()` is false. Where it is true (a
  `GOEXPERIMENT=runtimesecret` build on linux/amd64 or linux/arm64, not
  Android), a schedule that survives the garbage collection after its
  operation is in scope.
- Core dumps on Windows, darwin, NetBSD, AIX, Solaris and illumos, where no
  per-mapping exclusion is available; and copies the caller makes itself
  (bytes taken out of a `WithBytes` borrow, and `NewMemoryCopy` sources).
- `GOEXPERIMENT=boringcrypto` builds refusing to seal.
- Defects in the TPM, the trusted application or the secure-world firmware
  itself, and in providers or backends maintained outside this repository:
  report those to their authors, unless this package or a conformance suite
  is at fault.

## What to expect

These are targets, not contractual commitments:

| Step | Target |
|---|---|
| Acknowledge the report | 7 days |
| Initial assessment (accepted, needs info, or out of scope) | 14 days |
| Fix or mitigation for an accepted report | 90 days, sooner for critical issues |

You will be kept informed of progress, and credited in the release notes and
advisory unless you ask not to be.

## Disclosure policy

Coordinated disclosure. Please keep details private until a fixed release is
published, or until 90 days after the report, whichever comes first. If a fix
needs longer, we will ask before that date and explain why. The fix ships as a
new release whose `CHANGELOG.md` entry describes the issue, and a GitHub
security advisory is published once the release is available.

## Threat model

What each type protects against, and what it does not:

- [docs/memory-enclave/architecture.md](docs/memory-enclave/architecture.md#trust-boundaries): locked memory, guard pages, canary, core dumps.
- [docs/sealing/architecture.md](docs/sealing/architecture.md#what-each-mode-buys-against-a-live-memory-reader): what each sealing mode buys against a live-memory reader.
- [docs/sealing/engineering.md](docs/sealing/engineering.md#key-schedule-heap-exposure): the accepted key-schedule exposure.
- [docs/locked-memory-budget/architecture.md](docs/locked-memory-budget/architecture.md#trust-boundaries): what admission control does and does not bound.
- [docs/shutdown-sweep/architecture.md](docs/shutdown-sweep/architecture.md#trust-boundaries): who may call `WipeAll`.
- [docs/provider-conformance/architecture.md](docs/provider-conformance/architecture.md#trust-boundaries): what a passing conformance run proves.
- [docs/backend-conformance/architecture.md](docs/backend-conformance/architecture.md#trust-boundaries): what a passing backend conformance run proves.
- [docs/sealing/hardware-providers.md](docs/sealing/hardware-providers.md): the TPM provider's design.
- [docs/backends/arm-trustzone-design.md](docs/backends/arm-trustzone-design.md): the arm-trustzone backend's design.

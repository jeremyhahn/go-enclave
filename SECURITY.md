# Security policy

go-enclave holds key material in locked memory and seals it at rest. A defect
here is a security defect for everything built on it, so reports are welcome
and handled privately.

## Supported versions

go-enclave is pre-1.0. Only the **latest release** receives security fixes: the
newest tag (`vX.Y.Z-alpha`, `vX.Y.Z-rc.N`), or the newest `vX.Y.Z` once final
releases exist. Fixes ship as a new version and are never backported to an
older minor. Breaking changes land in a MINOR bump while the module is pre-1.0,
so upgrading to get a fix can require the steps in
[Upgrading](docs/README.md#upgrading).

| Version | Supported |
|---|---|
| Latest release | Yes |
| Anything older | No — upgrade |

Reports against the BSDs and Windows are in scope, though they are build-only
([test status](docs/memory-enclave/engineering.md#test-status)).

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a suspected
vulnerability.**

Report it privately through GitHub's private vulnerability reporting:

**<https://github.com/jeremyhahn/go-enclave/security/advisories/new>**

(the repository's **Security** tab → **Report a vulnerability**).

If you cannot use that form, contact the maintainer named in
[LICENSE](LICENSE) privately and ask for a secure channel before sending
details. A monitored security contact address has not been published yet; it
is pending the maintainer's confirmation and will be added here.

Please include:

- the go-enclave version (tag or commit), Go version, GOOS/GOARCH, and whether
  FIPS mode (`GOFIPS140`, `GODEBUG=fips140=only`) was in use;
- the affected API and sealing mode (`ModeRootKey` / `ModePerOperation`) and
  provider, if any;
- a minimal reproduction or proof of concept, and what an attacker gains;
- whether you believe it is already being exploited.

## Scope

In scope:

- **Memory exposure** — key material or plaintext reaching swap, the ordinary
  heap (beyond the documented key-schedule exposure), or another process;
  material surviving `Destroy` or `WipeAll`; unmapping or reading memory under a
  live borrow.
- **Residue** — copies of material left in this process after the API says
  they are gone, including in `providertest`'s own instruments.
- **Core-dump leaks** — enclave pages reaching a core dump on a platform where
  this package claims a per-mapping exclusion, or `CoreDumpsDisabled` reporting
  a protection that is not in force.
- **Cryptographic misuse** — a GCM key used past its documented message limit
  (or any nonce reuse that limit does not account for), unauthenticated or re-pairable
  envelopes, oracles in error reporting, non-approved cryptography on a sealing
  path.
- **Provider-contract violations by this package** — calling `UnsealRoot` more
  than once after it succeeded; holding a `Sealer` or `Sealed` mutex
  across a provider call (the init semaphore and the borrow of the private
  per-call enclave the provider writes into span `UnsealRoot` by design); silent
  re-keying after a sweep, a conformance-suite check that can pass a provider
  that violates the seam.
- **Admission-control bypass** — admitting allocations past an `Allocator`
  budget beyond what its documentation allows (the over-subscription
  `ForceLimit` reports, and `OpenIn`'s unadmitted transient key pages), or one
  failure destroying another caller's enclave.
- **Build and release supply chain** — the Makefile, pinned tool installation
  and checksum verification, `scripts/`, and the CI and release workflows
  (for example a tag or input that executes as code, or a release published
  from an ungated commit).

Out of scope — these are documented limits, not vulnerabilities (reports that
show the documentation understates them are in scope):

- An adversary who can read this process's live memory (`ptrace`,
  `/proc/<pid>/mem`, a debugger): a `Memory` is readable for its whole
  life, and with the software sealer or `ModeRootKey` the sealing keys are too.
- AES key schedules left on the heap by seals and opens, as described in
  [docs/sealing/engineering.md](docs/sealing/engineering.md#key-schedule-heap-exposure),
  in builds where `KeyScheduleErasure()` is false. Where it is true (a
  `GOEXPERIMENT=runtimesecret` build on linux/amd64 or linux/arm64 (not Android)), a schedule
  that survives the garbage collection after its operation IS in scope.
- Core dumps on Windows, darwin, NetBSD, AIX, Solaris and illumos, where no
  per-mapping exclusion is available; and copies the caller makes itself
  (bytes taken out of a `WithBytes` borrow, and `NewMemoryCopy` sources).
- `GOEXPERIMENT=boringcrypto` builds refusing to seal.
- Defects in third-party providers (TPM, HSM, KMS): report those to their
  authors, unless the seam or the conformance suite is at fault.

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
published, or until 90 days after the report, whichever is first; if a fix
needs longer we will ask before that date and explain why. The fix ships as a
new release whose `CHANGELOG.md` entry describes the issue, and an advisory is
published with the repository host once the release is available.

## Threat model

What each type protects against, and what it does not:

- [docs/memory-enclave/architecture.md](docs/memory-enclave/architecture.md#trust-boundaries) — locked memory, guard pages, canary, core dumps.
- [docs/sealing/architecture.md](docs/sealing/architecture.md#what-each-mode-buys-against-a-live-memory-reader) — what each sealing mode buys against a live-memory reader.
- [docs/sealing/engineering.md](docs/sealing/engineering.md#key-schedule-heap-exposure) — the accepted key-schedule exposure.
- [docs/locked-memory-budget/architecture.md](docs/locked-memory-budget/architecture.md#trust-boundaries) — what admission control does and does not bound.
- [docs/shutdown-sweep/architecture.md](docs/shutdown-sweep/architecture.md#trust-boundaries) — who may call `WipeAll`.
- [docs/provider-conformance/architecture.md](docs/provider-conformance/architecture.md#trust-boundaries) — what a passing conformance run proves.

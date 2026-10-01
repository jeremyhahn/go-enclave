# go-enclave documentation

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-01
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

One folder per capability, each with the same five files: `architecture.md`
(design, boundaries, rejected alternatives), `engineering.md` (exported
surface, invariants, errors, tests), `api.md` (the Go API per capability),
`cli.md` (none: this is a library) and `user.md` (task-oriented usage).
Every feature of this repository is documented in this layout; there are no
legacy documents to migrate.

| Feature | What it covers |
|---|---|
| [locked-memory](locked-memory/user.md) | `MemoryEnclave`: constructors, borrowing, `Freeze`, `Destroy` and its one panic, guard pages and canary, platform and core-dump matrix |
| [locked-memory-budget](locked-memory-budget/user.md) | `Allocator`, `RLIMIT_MEMLOCK` discovery, retuning, the process allocator, refunds for failed constructions |
| [sealing](sealing/user.md) | `SealedEnclave`, `Sealer` modes, the `KeyProtector`/`RootUnsealer` seam, contexts, `Openable`, FIPS, the key-schedule heap exposure |
| [shutdown-sweep](shutdown-sweep/user.md) | `WipeAll(ctx)`: admission, waiting for borrows, termination, the count and `SweepError` |
| [provider-conformance](provider-conformance/user.md) | `providertest.TestProvider(ctx, cfg)` for TPM/HSM/KMS provider authors |

## Upgrading from v0.6 to v0.7

v0.7 is a breaking MINOR release (pre-1.0). Every change, with before/after
code, is in the linked section.

| Change | Before (v0.6) | After (v0.7) | Details |
|---|---|---|---|
| Release report | `e.Destroy()` + `e.DestroyErr() error` | `e.Destroy() error` | [locked-memory](locked-memory/user.md#migrating-from-v06) |
| Windows core-dump status | `CoreDumpsDisabled()` returned `nil` | returns `ErrCoreDumpLimitUnsupported` | [locked-memory](locked-memory/user.md#migrating-from-v06) |
| OS layer dependency | `github.com/awnumar/memcall` | `golang.org/x/sys` only | [locked-memory](locked-memory/user.md#migrating-from-v06) |
| Shutdown sweep | `WipeAll() (int, error)`, fixed backoff | `WipeAll(ctx) (int, error)`, waits for borrows | [shutdown-sweep](shutdown-sweep/user.md#migrating-from-v06) |
| Sweep findings | joined untyped errors | `*SweepError{Corrupt, Unwiped}`; new `ErrSweepInProgress` | [shutdown-sweep](shutdown-sweep/user.md#migrating-from-v06) |
| Seal / open | `NewSealed(data)`, `Seal(data)`, `Open()`, `OpenWith(a)` | each takes `ctx` first | [sealing](sealing/user.md#migrating-from-v06) |
| Provider seam | `Protect(key)`, `Unprotect(blob, key)`, `UnsealRoot(dst)` | each takes `ctx` first | [sealing](sealing/user.md#migrating-from-v06) |
| Provider failures on open | returned bare | joined under new `ErrOpenFailed` | [sealing](sealing/user.md#migrating-from-v06) |
| `SealedEnclave.Destroy` | waited for in-flight `Open` | does not wait | [sealing](sealing/user.md#migrating-from-v06) |
| Conformance suite | `TestProvider(cfg)` | `TestProvider(ctx, cfg)`; new `ErrAborted` | [provider-conformance](provider-conformance/user.md#migrating-from-v06) |

The budget API (`Allocator`, `SetAllocator`, `ProcessAllocator`) is unchanged.

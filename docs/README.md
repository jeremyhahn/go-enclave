# go-enclave documentation

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-04
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

One folder per capability, each with the same five files: `architecture.md`
(design, boundaries, rejected alternatives), `engineering.md` (exported
surface, invariants, errors, tests), `api.md` (the Go API per capability),
`cli.md` (none: this is a library) and `user.md` (task-oriented usage).
Every feature of this repository is documented in this layout; there are no
legacy documents to migrate.

| Feature | What it covers |
|---|---|
| [locked-memory](locked-memory/user.md) | `MemoryEnclave`: constructors, borrowing, `Freeze`, `Destroy` and canary corruption, guard pages and canary, platform and core-dump matrix |
| [locked-memory-budget](locked-memory-budget/user.md) | `Allocator`, `RLIMIT_MEMLOCK` discovery, retuning, the process allocator, refunds for failed constructions |
| [sealing](sealing/user.md) | `SealedEnclave`, `Sealer` modes, the `KeyProtector`/`RootUnsealer` seam, contexts, `Openable`, FIPS, the key-schedule heap exposure and its erasure under `runtime/secret` |
| [shutdown-sweep](shutdown-sweep/user.md) | `WipeAll(ctx)`: admission, waiting for borrows, termination, the count and `SweepError` |
| [provider-conformance](provider-conformance/user.md) | `providertest.TestProvider(ctx, cfg)` for TPM/HSM/KMS provider authors |

## Upgrading from v0.7

Breaking changes since v0.7, pre-1.0. Before/after code is in the linked
sections.

| Change | Before (v0.7) | After | Details |
|---|---|---|---|
| Comparison | `EqualTo(b) bool`, `EqualToErr(b) (bool, error)` | `EqualTo(b) (bool, error)` | [locked-memory](locked-memory/user.md#migrating-from-v07) |
| Canary corruption | `Destroy` panicked | `Destroy` returns `ErrEnclaveCorrupted`; the next `WipeAll` reports it too | [locked-memory](locked-memory/user.md#migrating-from-v07) |
| Unlocked and string accessors | `Open`, `OpenString`, `NewMemoryEnclaveFromString` | deprecated (still work); use `WithBytes`, `NewMemoryEnclave` | [locked-memory](locked-memory/user.md#migrating-from-v07) |
| Retune refusal type | `*LimitError` | `*BudgetInUseError` | [locked-memory-budget](locked-memory-budget/user.md#migrating-from-v07) |
| Nil `*Allocator` | `New`/`NewSized` panicked | `ErrNilAllocator` from every method that can fail | [locked-memory-budget](locked-memory-budget/user.md#migrating-from-v07) |
| Sealer provider | `WithProvider(p)`, `WithMode(m)`; `ErrProviderMode`, `ErrInvalidMode` | `WithKeyProtector(kp)` or `WithRootUnsealer(ru)`; `ErrInvalidProvider` | [sealing](sealing/user.md#migrating-from-v07) |
| Provider health | `WithProviderHealth(fn)` | provider implements `HealthReporter` | [sealing](sealing/user.md#migrating-from-v07) |
| Sealed release | `SealedEnclave.Destroy()` | `SealedEnclave.Destroy() error` | [sealing](sealing/user.md#migrating-from-v07) |

## Upgrading from v0.6 to v0.7

v0.7 is a breaking MINOR release (pre-1.0). Every change, with before/after
code, is in the linked section.

| Change | Before (v0.6) | After (v0.7) | Details |
|---|---|---|---|
| Release report | `e.Destroy()` + `e.DestroyErr() error` | `e.Destroy() error` | [locked-memory](locked-memory/user.md#migrating-from-v06) |
| Unwiped release | matched `ErrReleasedWithoutWipe` **and** `ErrLockedMemoryUnavailable` | matches `ErrReleasedWithoutWipe` only; `UnwipedReleaseError.Cause` is the raw OS error | [locked-memory](locked-memory/user.md#migrating-from-v06) |
| Windows core-dump status | `CoreDumpsDisabled()` returned `nil` | returns `ErrCoreDumpLimitUnsupported` | [locked-memory](locked-memory/user.md#migrating-from-v06) |
| OS layer dependency | `github.com/awnumar/memcall` | `golang.org/x/sys` only | [locked-memory](locked-memory/user.md#migrating-from-v06) |
| Shutdown sweep | `WipeAll() (int, error)`, fixed backoff | `WipeAll(ctx) (int, error)`, waits for borrows | [shutdown-sweep](shutdown-sweep/user.md#migrating-from-v06) |
| Sweep findings | joined untyped errors | `*SweepError{Corrupt, Unwiped}`; new `ErrSweepInProgress` | [shutdown-sweep](shutdown-sweep/user.md#migrating-from-v06) |
| Seal / open | `NewSealed(data)`, `Seal(data)`, `Open()`, `OpenWith(a)` | each takes `ctx` first | [sealing](sealing/user.md#migrating-from-v06) |
| Provider seam | `Protect(key)`, `Unprotect(blob, key)`, `UnsealRoot(dst)` | each takes `ctx` first | [sealing](sealing/user.md#migrating-from-v06) |
| Provider failures on open | returned bare | joined under new `ErrOpenFailed` | [sealing](sealing/user.md#migrating-from-v06) |
| `SealedEnclave.Destroy` | waited for in-flight `Open` | does not wait | [sealing](sealing/user.md#migrating-from-v06) |
| A sweep destroying a per-call key | `ModeRootKey` reported `ErrSealerWiped` | `ErrEnclaveDestroyed` unless a hierarchy key is dead | [sealing](sealing/user.md#migrating-from-v06) |
| Opened plaintext | `Open`/`OpenWith` returned a writable enclave | returns a frozen (read-only) enclave | [sealing](sealing/user.md#migrating-from-v06) |
| Conformance suite | `TestProvider(cfg)` | `TestProvider(ctx, cfg)`; new `ErrAborted` | [provider-conformance](provider-conformance/user.md#migrating-from-v06) |

The budget API (`Allocator`, `SetAllocator`, `ProcessAllocator`) is unchanged.

# Locked-memory budget and admission — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-01
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Exported surface

| Identifier | Contract |
|---|---|
| `NewAllocator(maxBytes int64) (*Allocator, error)` | Budget in locked bytes. Never checks a ceiling, on any path. |
| `NewAllocatorWithinRLimit(maxBytes int64) (*Allocator, error)` | As `NewAllocator`, but refuses a budget above a **bounded** ceiling, and keeps that check for life on every raise. |
| `(*Allocator).New(data []byte) (*MemoryEnclave, error)` | Admitted `NewMemoryEnclave`; wipes `data` on every path, including refusal. |
| `(*Allocator).NewSized(n int) (*MemoryEnclave, error)` | Admitted `NewMemoryEnclaveSized`. |
| `(*Allocator).SetLimit(newLimit int64) error` | Raise, or lower without going below reservations. All-or-nothing. |
| `(*Allocator).ForceLimit(newLimit int64) (int64, error)` | Accepts any non-negative budget; returns the over-subscription in bytes. |
| `(*Allocator).TransferTo(dst *Allocator, n int64) error` | Moves `n` bytes of headroom to `dst` in one operation. |
| `(*Allocator).InUse() int64` / `Limit() int64` / `Available() int64` | Observability snapshots; never an admission gate. `Available` clamps at 0. |
| `SetAllocator(a *Allocator) error` | Installs the process allocator. One-shot. Binary only. |
| `ProcessAllocator() (*Allocator, error)` | Returns the installed allocator, lazily installing the default. Libraries call this. |
| `DiscoverLockedMemoryLimit() (LockedMemoryLimit, error)` | Snapshot of the ceiling and its source. |
| `LockedMemoryLimit{Bytes int64; Bounded bool; Source LimitSource}` | `Bytes` is a ceiling only when `Bounded`. |
| `LimitSource`: `LimitUnknown`, `LimitRLimit`, `LimitUnlimited`, `LimitNotEnforced`, `LimitUnsupported` | Where the figure came from. Only `LimitRLimit` is `Bounded`. |
| `BudgetError{Requested, InUse, Limit int64}` | Matches `ErrBudgetExhausted`. `InUse` is never negative and may exceed `Limit` after `ForceLimit`. |
| `LimitError{Requested, InUse, Limit int64}` | Matches `ErrBudgetInUse`. `Limit` is the unchanged budget. |
| `RLimitError{Requested int64; Limit LockedMemoryLimit}` | Matches `ErrBudgetExceedsRLimit`. |
| `LimitDiscoveryError{Cause error}` | Matches `ErrLimitDiscoveryFailed`; unwraps to the `getrlimit` failure. |

## Invariants

1. **Charge = `LockedSize(n)`.** Admission is the CAS `charge > free → refuse`,
   taken **before** any `mmap`; a refusal makes no syscall. A non-positive or
   unmappable size is `ErrInvalidSize` and never touches the counter.
2. **`free = limit − reserved`**, where `reserved` is the page-rounded total of
   live reservations. It is negative exactly when reservations exceed the
   budget, which only `ForceLimit` produces (e.g. `ForceLimit(0)` with one page
   reserved leaves `free = −pageSize`). While `free` is below a request's charge
   that request is refused, so nothing is admitted until reservations fall to
   `limit − charge` or below.
3. **A reservation lives exactly as long as the enclave's pages.** `Destroy`
   returns it once (guarded by `sync.Once`) after the pages are unmapped — or
   after a corrupted or unwiped release, both of which do unmap. A refused
   release keeps it.
4. **A failed construction's charge is decided once, at rollback.** If the
   rollback left the pages still `mlock`'d, the charge is kept and attached to
   the orphan record; otherwise it is refunded at once (the record, if any,
   carries no refund). An attached charge then stays until a `WipeAll` retry
   **unmaps** the pages — a retry that unlocks them but is refused the
   `munmap` keeps the record, and the charge, for the next sweep
   ([shutdown-sweep](../shutdown-sweep/engineering.md)).
5. **Refused retunes change nothing.** `SetLimit` and `TransferTo` either apply
   the whole change or none of it.
6. **Ceiling checks apply only to opted-in allocators and only to raises.** An
   allocator from `NewAllocatorWithinRLimit` (or the default process allocator
   when the ceiling binds) re-reads the ceiling on every `SetLimit` call —
   before taking the retune lock, so it cannot yet know whether the call is a
   raise — and consults the reading only for a raise; it also re-reads it when
   credited by `TransferTo`. A failed reading refuses the raise with
   `ErrLimitDiscoveryFailed`. Lowerings are never refused on a ceiling.
   `ForceLimit` reads no ceiling and refuses nothing but a negative budget.
7. **`TransferTo` passes through "in neither", never "in both".** Source is
   debited before the destination is credited, with both retune locks held in
   ascending allocator-id order. A successful reservation and a refund take no
   lock. A refusal may take one allocator's read lock to build its
   `BudgetError` (`budgetSnapshot`), and `InUse` takes it too; neither holds any
   other lock while doing so, so neither can join a cycle.
8. **One process allocator.** `SetAllocator` fails with `ErrAllocatorInstalled`
   once any is installed, including the lazy default. The first
   `ProcessAllocator` call installs a default sized to the discovered ceiling
   when it binds (keeping the ceiling check), `0` for a zero ceiling, and
   `math.MaxInt64` when no ceiling binds. A discovery failure installs nothing;
   a later call retries.

## Error semantics

| Error | When | Fail-closed? |
|---|---|---|
| `ErrBudgetExhausted` (`*BudgetError`) | `New`/`NewSized`/`OpenWith` would exceed the budget | Yes — refused before any locked memory is requested. |
| `ErrInvalidBudget` | `maxBytes <= 0` at construction; negative `SetLimit`/`ForceLimit`; a transfer that would overflow `dst`'s `int64` budget | Yes |
| `ErrBudgetInUse` (`*LimitError`) | Lowering (or transferring away) below current reservations | Yes — nothing changed. |
| `ErrInvalidTransfer` | `n <= 0`, `dst == nil`, or `dst` is the source | Yes |
| `ErrBudgetExceedsRLimit` (`*RLimitError`) | Budget or raise above a bounded ceiling (opted-in allocators) | Yes |
| `ErrLimitDiscoveryFailed` (`*LimitDiscoveryError`) | `getrlimit` failed: construction, an opted-in raise, or the lazy default | Yes — nothing was compared, so nothing passed. |
| `ErrNilAllocator` | `SetAllocator(nil)`; `OpenWith(ctx, nil)` | Yes — never falls back to unbudgeted. |
| `ErrAllocatorInstalled` | Second `SetAllocator`, or `SetAllocator` after a `ProcessAllocator` call that installed the lazy default (a discovery failure installs nothing) | Yes |
| `ErrLockedMemoryUnavailable` | Admitted, but the kernel refused | Reservation refunded unless locked pages were left behind (invariant 4). |

## Platform contract for discovery

| GOOS | Discovery | `CAP_IPC_LOCK` considered |
|---|---|---|
| linux | `getrlimit(RLIMIT_MEMLOCK)` soft limit, `RLIM_INFINITY` = all bits set | Yes — effective set of the **calling thread** (`LimitNotEnforced`), and only in the initial user namespace (`/proc/self/uid_map` = `0 0 4294967295`; unreadable counts as enforced). Root of a rootless container gets `LimitRLimit`. |
| darwin, freebsd, netbsd, openbsd, dragonfly | soft limit, `RLIM_INFINITY` = `MaxInt64` | No capability check exists; a finite limit is reported as enforced |
| windows, aix, solaris, illumos | none — `LimitUnsupported`, nothing refused | — |

The BSD discovery path is compiled by `make cross-build` but executed by no CI
host; its classification (`classifyRlimit`) is shared with Linux and
unit-tested against both `RLIM_INFINITY` sentinels.

## Configuration and persistence

None. Budgets are set in code. Nothing is persisted.

## Test strategy

- Unit and race tests (`make test`, `make coverage`) across `-cpu=1,2,8`.
- `Allocator.stalled` — a nil-in-production hook inside the retune CAS loop —
  parks a lowering in the window a racing admission must hit, making the
  over-commit race deterministic.
- `setLimit` / `transferTo` take the ceiling reading as a parameter, so a failed
  `getrlimit` is testable on a healthy host; `LockedMemoryLimit.refuse` and
  `classifyRlimit` cover every ceiling shape without privilege.
- `discoverProcessLimit` and `resetProcessAllocatorForTest` exercise the lazy
  default and one-shot installation.
- Linux tests lower `RLIMIT_MEMLOCK` in a subprocess to reach admitted-but-refused
  paths and compare against `/proc/self/status` `VmLck`.

## Observability

`InUse`, `Limit`, `Available`, the fields of `BudgetError`/`LimitError`/
`RLimitError`, the `ForceLimit` excess, and `LockedMemoryLimit.Source`
(its `String()` is suitable for logs). No logs or metrics are emitted.

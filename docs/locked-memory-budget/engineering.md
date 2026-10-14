# Locked-memory budget and admission — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-14
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Exported surface

| Identifier | Contract |
|---|---|
| `NewAllocator(maxBytes int64) (Allocator, error)` | Budget in locked bytes. Never checks a ceiling, on any path. `Allocator` is an interface whose implementation is internal; a failure returns a nil interface. |
| `NewAllocatorWithinRLimit(maxBytes int64) (Allocator, error)` | As `NewAllocator`, but refuses a budget above a **bounded** ceiling, and keeps that check for life on every raise. |
| `Allocator.New(data []byte) (ByteAccess, error)` | Admitted `NewMemory`; wipes `data` on every path, including refusal. |
| `Allocator.NewSized(n int) (ByteAccess, error)` | Admitted `NewMemorySized`; the enclave is also a `Freezer`. |
| `Allocator.SetLimit(newLimit int64) error` | Raise, or lower without going below reservations. All-or-nothing. |
| `Allocator.ForceLimit(newLimit int64) (int64, error)` | Accepts any non-negative budget; returns the over-subscription in bytes. |
| `Allocator.TransferTo(dst Allocator, n int64) error` | Moves `n` bytes of headroom to `dst` in one operation. A `dst` this package did not build: `ErrAllocatorNotConstructed`. |
| `Allocator.InUse() int64` / `Limit() int64` / `Available() int64` | Observability snapshots; never an admission gate. `Available` clamps at 0. |
| `Allocator.Name() string` / `Import(ctx, material, opts...) (Handle, error)` | The locked-memory `Backend` (name `"locked-memory"`) and `Importer`: `Import` is an admitted `New` under the [backends](../backends/engineering.md) contract. An `Allocator` is never registered; `(*Memory).Backend()` returns the one that admitted the enclave. |
| `SetAllocator(a Allocator) error` | Installs the process allocator. One-shot. Binary only. Nil: `ErrNilAllocator`; an `Allocator` this package did not build: `ErrAllocatorNotConstructed`. |
| `ProcessAllocator() (Allocator, error)` | Returns the installed allocator, lazily installing the default. Libraries call this. |
| `DiscoverLockedMemoryLimit() (LockedMemoryLimit, error)` | Snapshot of the ceiling and its source. |
| `LockedMemoryLimit{Bytes int64; Bounded bool; Source LimitSource}` | `Bytes` is a ceiling only when `Bounded`; it is populated for `LimitNotEnforced` and zero when nothing was read. |
| `LimitSource`: `LimitUnknown`, `LimitRLimit`, `LimitUnlimited`, `LimitNotEnforced`, `LimitUnsupported` | Where the figure came from; each value: [api.md](api.md#limitsource-values). Only `LimitRLimit` is `Bounded`. |
| `BudgetError{Requested, InUse, Limit int64}` | Matches `ErrBudgetExhausted`. `Requested` is the page-rounded charge. `InUse` is never negative and may exceed `Limit` after `ForceLimit`. |
| `BudgetInUseError{Requested, InUse, Limit int64}` | Matches `ErrBudgetInUse`. `Requested` is the budget asked for (for `TransferTo`, what the source would be left with); `Limit` is the unchanged budget. |
| `RLimitError{Requested int64; Limit LockedMemoryLimit}` | Matches `ErrBudgetExceedsRLimit`. `Limit` is always `Bounded`. |
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
   `limit − charge` or below. Holding the remainder rather than the usage makes
   admit, release, raise and lower each one signed adjustment of one word, so a
   single CAS linearizes a lowering against an admission; a separate limit and
   usage counter would be check-then-act. The predicate involves no addition,
   so an oversized request cannot overflow into admission. `limit` is a
   reporting shadow that admission never reads.
3. **A reservation lives exactly as long as the enclave's pages.** `Destroy`
   returns it once (guarded by `sync.Once`) after the pages are unmapped — or
   after a corrupted or unwiped release, both of which do unmap. A refused
   release keeps it.
4. **A failed construction's charge is decided once, at rollback.** `New` and
   `NewSized` share one admission step (`admit`) with one refund closure. If
   the rollback left the pages still `mlock`'d, the charge is kept and the
   closure becomes the orphan's release; otherwise it is refunded at once (the
   orphan, if any, carries no refund). An attached charge then stays until a
   `WipeAll` retry **unmaps** the pages — a retry that unlocks them but is
   refused the `munmap` keeps the orphan, and the charge, for the next sweep
   ([shutdown-sweep](../shutdown-sweep/engineering.md)). An orphan is booked
   exactly as a `Destroy`ed enclave is, so the refund runs at most once.
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
   A transfer is checked on the destination even though it is
   process-conservative: the check judges each budget alone, not the process
   total.
7. **`TransferTo` passes through "in neither", never "in both".** Source is
   debited before the destination is credited, with both retune locks held in
   ascending allocator-id order (ids come from a process-wide counter, not
   pointer comparison). A successful reservation and a refund take no
   lock. A refusal may take one allocator's read lock to build its
   `BudgetError` (`budgetSnapshot`), and `InUse` takes it too; neither holds any
   other lock while doing so, so neither can join a cycle.
8. **One process allocator.** `SetAllocator` fails with `ErrAllocatorInstalled`
   once any is installed, including the lazy default. The first
   `ProcessAllocator` call installs a default sized to the discovered ceiling
   when it binds (keeping the ceiling check), `0` for a zero ceiling, and
   `math.MaxInt64` when no ceiling binds. A discovery failure installs nothing;
   a later call retries. The installed allocator is never replaced, which would
   strand live reservations on an allocator nothing admits against. The slot is
   the package's generic install-once process singleton (`singleton.go`).
9. **Readers never see ungranted headroom.** Where a retune writes both words,
   `limit` is stored before `free` is credited, so a reader that does not take
   the retune mutex may overstate usage but never understates it. A refusal
   that reads without the mutex can still pair
   words from either side of a retune: mid-raise on an over-subscribed
   allocator `limit − free` can wrap, and a lowering between its two loads
   gives `free > limit`. `budgetSnapshot` rejects any negative difference and
   re-reads under the read lock, so `BudgetError.InUse` is never negative while
   the ordinary refusal takes no lock.
10. **A copy is the same allocator.** `Allocator` is an interface over one
    internal implementation holding one unexported state; every copy admits
    against the same budget, so it can never admit the same headroom twice.
    `SetAllocator` and `TransferTo` need that state, so they refuse an
    `Allocator` implemented outside this package with
    `ErrAllocatorNotConstructed`.

## Error semantics

| Error | When | Fail-closed? |
|---|---|---|
| `ErrBudgetExhausted` (`*BudgetError`) | `New`/`NewSized`/`OpenIn` would exceed the budget | Yes — refused before any locked memory is requested. |
| `ErrInvalidBudget` | `maxBytes <= 0` at construction; negative `SetLimit`/`ForceLimit`; a transfer that would overflow `dst`'s `int64` budget | Yes |
| `ErrBudgetInUse` (`*BudgetInUseError`) | Lowering (or transferring away) below current reservations | Yes — nothing changed. |
| `ErrInvalidTransfer` | `n <= 0`, `dst == nil`, or `dst` is the source or a copy of it | Yes |
| `ErrBudgetExceedsRLimit` (`*RLimitError`) | Budget or raise above a bounded ceiling (opted-in allocators) | Yes |
| `ErrLimitDiscoveryFailed` (`*LimitDiscoveryError`) | `getrlimit` failed: construction, an opted-in raise, or the lazy default | Yes — nothing was compared, so nothing passed. |
| `ErrNilAllocator` | `SetAllocator(nil)` (a nil `Backend` given to `OpenIn` is `ErrInvalidBackend`) | Yes — never falls back to unbudgeted. |
| `ErrAllocatorNotConstructed` | `SetAllocator` or `TransferTo` given an `Allocator` this package did not build | Yes — it has no budget to admit against. |
| `ErrAllocatorInstalled` | Second `SetAllocator`, or `SetAllocator` after a `ProcessAllocator` call that installed the lazy default (a discovery failure installs nothing) | Yes |
| `ErrLockedMemoryUnavailable` | Admitted, but the kernel refused | Reservation refunded unless locked pages were left behind (invariant 4). |

All of these are declared in [errors.go](../../errors.go). `BudgetError` and
`BudgetInUseError` render as `<sentinel>: <Requested> bytes requested, <InUse>
of <Limit> bytes in use`, and `RLimitError` as `<sentinel>: <Requested> bytes
requested, <Source> is <Bytes> bytes`. `LimitDiscoveryError` has the shared
cause shape of [locked-memory](../locked-memory/engineering.md#error-semantics):
the sentinel's text, `": "` and the cause.

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
- `allocatorState.stalled` — a nil-in-production hook in `withdrawLocked`'s CAS
  window — parks a lowering in the window a racing admission must hit, making the
  over-commit race deterministic. `reserve` deliberately duplicates the loop
  rather than sharing it, so the seam stays off the admission path.
- `TestAllocator_Retune_RacesAdmission` arranges rounds of one-page claims with
  known supply and demand instead of running a storm: in a storm, admitters
  holding pages across preemption starve the lowerings, so coverage depends on
  load. A double-spend in the contested shape is detectable only with more than
  one CPU. Each round needs RLIMIT_MEMLOCK of at least `retuneActors` (8)
  pages. Race tests bound their run by the side they assert about, with a
  minimum-sample floor and a vacuity control.
- `TestAllocator_StaysWithinItsCachelineBudget` holds `allocatorState` to 64 bytes
  (a fixed budget, not a discovered line size; it is exactly 64 on amd64) with
  `free` and `limit` in one line. A new field must justify its place on the hot
  type, or the hot pair moves into its own aligned struct.
- `BenchmarkRefusalSerial` / `BenchmarkRefusalParallel` guard that the ordinary
  refusal takes no lock. A refusal performs only atomic loads, so concurrent refusers share
  a read-only cacheline and parallel refusal is cheaper per operation than
  serial (parallel/serial about 0.6–0.75). Any read-modify-write on the path —
  a mutex, even `RWMutex.RLock`, or one no-op `free.Add(0)` — serializes
  refusers and pushes the ratio above 1; the bare atomic on `free` is the worst
  case, because it contends on the line every refuser loads. Compare the
  ratio, not absolute nanoseconds, with `benchstat` before and after changing
  the refusal path. It is not a CI gate: thresholds on shared runners are noise.
- `setLimit` / `transferTo` take the ceiling reading as a parameter, so a failed
  `getrlimit` is testable on a healthy host; `LockedMemoryLimit.refuse` and
  `classifyRlimit` cover every ceiling shape without privilege.
- `discoverProcessLimit` and `resetProcessAllocatorForTest` exercise the lazy
  default and one-shot installation.
- Linux tests lower `RLIMIT_MEMLOCK` in a subprocess to reach admitted-but-refused
  paths and compare against `/proc/self/status` `VmLck`.

## Observability

`InUse`, `Limit`, `Available`, the fields of `BudgetError`/`BudgetInUseError`/
`RLimitError`, the `ForceLimit` excess, and `LockedMemoryLimit.Source`
(its `String()` is suitable for logs). No logs or metrics are emitted.

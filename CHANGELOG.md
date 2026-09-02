# Changelog

All notable changes to go-enclave are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **The `RLIMIT_MEMLOCK` check is now sticky: an allocator built by
  `NewAllocatorWithinRLimit` carries it for life.** (#46) `SetLimit` re-reads the
  ceiling and refuses to raise that allocator's budget above it with
  `ErrBudgetExceedsRLimit`, the same sentinel and the same `RLimitError` the
  constructor uses. `TransferTo` applies it to the allocator it CREDITS, since a
  transfer is a raise on the receiving side.

  Before this, the check bound a budget for exactly as long as it took to call
  `SetLimit`: #43 refused an over-ceiling budget at construction and #44 let the
  same allocator be raised straight back over it, so two entry points to one
  allocator disagreed about whether the kernel ceiling applied. It was never a
  safety hole — admission fails safe with `ErrLockedMemoryUnavailable` — but it
  lost the diagnostic the check exists for, which is failing at the setting that
  caused the problem rather than at peak load.

  **The ceiling is read fresh on every raise, never cached.** It moves: a
  setrlimit from any thread, a container resized underneath the process. A
  budget compared against a figure from startup would refuse a raise the kernel
  now permits, or permit one it now would not. The syscall is on a control-plane
  path that runs rarely, and it is taken outside the retune mutex so it cannot
  stall other retunes or the observability getters. **Nothing was added to the
  admission path**, which still reads no ceiling at all.

  Three boundaries, each with a test that fails without it:

  - **Opt-in.** A plain `NewAllocator` allocator is never checked, on any path.
    Applying the ceiling to every allocator would break callers who chose the
    unchecked constructor deliberately.
  - **Raises only.** A lowering is never refused on a ceiling, or an
    over-ceiling allocator could not move back towards compliance.
  - **`ForceLimit` overrides it**, as it overrides every other refusal on this
    type — it is the method that exists to do what `SetLimit` refuses. That is
    documented on the method rather than left implicit, so the contract is not
    mistaken for one that cannot be bypassed, and it is the escape hatch when
    discovery itself fails. The allocator stays bound afterwards: an override is
    not an opt-out.

  A discovery failure during a raise is reported as `ErrLimitDiscoveryFailed`
  and refuses the raise — nothing was compared, so nothing passed.


### Added

- **`NewMemoryEnclaveCopy(src []byte) (*MemoryEnclave, error)` — a constructor
  that copies without consuming its source.** `NewMemoryEnclave` takes ownership
  and wipes the caller's slice on every return path; that stays the default and
  stays right. Some callers cannot honor it — a buffer owned by someone else, a
  fixture handed back on every call, material compared against the bytes it was
  built from — and they were composing `NewMemoryEnclaveSized` + `WithBytes` +
  `Destroy`-on-error by hand instead, the same eight lines in two packages of one
  consumer already. Omitting that `Destroy` leaks a locked page on a path nobody
  tests, which is the kind of mistake a constructor should make impossible rather
  than document.

  **The result is FROZEN read-only**, matching `NewMemoryEnclave` and not
  `NewMemoryEnclaveSized`. The material is complete when the constructor returns,
  so writable pages would buy nothing and would give up the protection against a
  stray write through a retained `Open` slice. The decision is in the doc comment
  because guessing it wrong is not an error — a write through frozen pages
  **faults the process** — and because the two older constructors disagree, so a
  caller generalizes from whichever it met first.

  **What the caller accepts is stated in the doc comment, not glossed:** an
  unprotected copy of the material remains on the ordinary Go heap for as long as
  the source lives. That is exactly what this package exists to avoid, and this
  constructor does not undo it — it protects the copy it holds and makes no claim
  about the source, which nothing here can wipe later because only the caller
  knows when it is done. Material that should never touch the heap at all belongs
  in `NewMemoryEnclaveSized`.

  `NewMemoryEnclave` is now implemented as this constructor plus the wipe, so the
  two cannot drift apart in the mapping, freeze or cleanup sequence — which is the
  same divergence the duplicated hand-rolled composition was heading for.

- **`(*MemoryEnclave) Freeze() error` — restore fault-on-write once a sized
  enclave's fill is done.** `NewMemoryEnclave` freezes its pages read-only as
  the material moves in, so a write through a slice retained past its borrow
  faults. `NewMemoryEnclaveSized` cannot: pages that have to be filled cannot
  arrive read-only, and until now they stayed writable for the enclave's whole
  LIFETIME. A stray write there silently corrupted the material, which is a
  strictly worse failure than a fault, and the window was the lifetime rather
  than the fill. `Freeze` closes it — after it returns, a sized enclave has
  exactly the protection a move-constructed one has.

  It is **idempotent** and **not reversible**. A second `Freeze` is a no-op, and
  so is freezing an enclave that arrived frozen, so a caller handed an enclave
  can freeze it without knowing which constructor built it. There is
  deliberately no `Melt`: a re-mutable enclave reopens the window this closes,
  and the fill is the only reason the pages were ever writable.

  It takes the **write lock**, so it waits out in-flight borrows exactly as
  `Destroy` does. That is not incidental: under the read lock the `mprotect`
  could land between two stores of a goroutine that is still filling, and a
  method whose purpose is to turn silent corruption into a fault would be
  manufacturing the fault itself. It must therefore never be called from inside
  a borrow on the same enclave, which deadlocks like any other nested call.

  A refused `mprotect` returns `ErrLockedMemoryUnavailable` (as a
  `LockedMemoryError`) and leaves the enclave **alive, writable and otherwise
  untouched** — the caller keeps what it had and knows the property was not
  established. `NewMemoryEnclave` destroys the mapping on that same failure only
  because a constructor cannot hand back a half-built enclave; here the caller
  already owns one, and destroying it underneath them would turn a failed
  hardening step into lost key material.

  The name is `Freeze`, not `Seal`. It names the mechanism, matches the internal
  `mapping.freeze` and memguard's spelling, and does not collide with the AEAD
  `Seal` that consumers of this library have in scope at exactly the call sites
  that hold key material — the same reasoning that keeps the type from being
  called a "secret".

  What it costs, stated because it is a real trade: freezing moves the
  material's wipe at `Destroy` time BEHIND a syscall that can be refused.
  `Destroy` wipes first, before anything deniable, while the region is still
  writable; a frozen region has to be made writable again first. A denied
  `mprotect` sends any enclave down #38's unwiped-release path — pages handed
  back with a bare `munmap`, `DestroyErr` reporting `ErrReleasedWithoutWipe` —
  but **a frozen enclave is the only kind whose material is still there when it
  goes**, because `wipeAndVerify` skips its early wipe exactly when the pages are
  read-only. That is measured from inside the unmap seam, in both arms, rather
  than argued. Nothing leaks either way: the pages were `mlock`'d for their whole
  life and the kernel zeroes an anonymous page before reuse. That is already true of every enclave from
  `NewMemoryEnclave` and `NewMemoryEnclaveCopy`, and an `mprotect` refused on a
  region this process already owns is a far narrower hazard than an unbounded
  window in which a retained slice rewrites a key with nothing to announce it.

  The evidence is by execution, not by assertion: a subprocess fills a sized
  enclave, freezes it, and writes through a retained slice — it must die, and
  must not have printed its survival marker. The in-process control does the
  same write on an unfrozen enclave and requires it to SUCCEED, since an
  implementation that froze sized enclaves at construction would break every
  consumer of them. (#6)

- **`NewAllocatorWithinRLimit(maxBytes int64) (*Allocator, error)` — the
  startup check for a locked-memory budget.** It discovers the process's
  `RLIMIT_MEMLOCK` and **refuses** a budget above it, returning
  `ErrBudgetExceedsRLimit` (as an `*RLimitError`) naming both the budget and the
  discovered ceiling. A service whose budget was never satisfiable learns it
  while starting, from an error that names the number to change, instead of at
  peak load from an allocation failure several layers from the setting that
  caused it.

  It fails closed rather than warning and continuing: a guard that reports a
  problem somewhere nobody correlates with the failure it later causes is the
  pattern this package exists to remove. And it is a **constructor error**, not
  an exit — a library must never `os.Exit`, `log.Fatal` or panic over a host's
  resource configuration, so the decision stays with the application.

  `NewAllocator` is unchanged and still accepts any positive budget, so nothing
  existing changes behavior.

- **`DiscoverLockedMemoryLimit() (LockedMemoryLimit, error)`**, with
  `LimitSource` and its `String`, for **deriving** a budget from the host rather
  than guessing one — and for logging where the figure came from. "8 MiB because
  `RLIMIT_MEMLOCK` said so" and "8 MiB because nothing bounded us and the config
  asked for it" are the same number and different facts.

  Three readings are handled explicitly rather than arithmetically. `RLIM_INFINITY`
  is all-bits-set, which as an `int64` is `-1` — below every budget, so treating
  it as a number would refuse them all; it reports as unlimited, and so does a
  finite limit too large to represent as the `int64` a budget is. A process
  holding **`CAP_IPC_LOCK`** may exceed the limit outright, so the figure is
  reported as `LimitNotEnforced` and refuses nothing: failing a correctly
  configured privileged service at startup, over a number the kernel will not
  apply to it, is worse than the late failure this check exists to prevent.

  The reading is a **snapshot and an upper bound on what may be assumed**, never
  a guarantee. The ceiling is process-wide and shared, a cgroup v2 `memory.max`
  frequently binds below it in a container, and it can move afterwards.
  `ErrLockedMemoryUnavailable` remains the authority on what may actually be
  locked. It is read once, at construction, and never on the allocation path.

  The ceiling is read on **Linux and on the five BSDs**, all of which define
  `RLIMIT_MEMLOCK`. `LimitUnsupported` is reported only where a platform
  genuinely exposes none — Windows bounds a working-set size instead — because
  reporting it where a ceiling *was* readable is a fail-open guard: the budget
  was checkable, the constructor said nothing, and the failure lands later under
  allocation pressure. There the constructor refuses nothing, which is the
  deliberate contract: a diagnostic that cannot run is absent, not violated, and
  refusing every budget would push callers back to the unchecked constructor and
  delete the check where it does work. `LimitUnsupported` rather than
  `LimitUnlimited` because "we did not look" is not the same claim as "the
  kernel says there is no ceiling".

  The BSD path has no CI — this repository's runners are Linux-only. Its
  classification is shared with Linux in `classifyRlimit` and tested against
  **both** platforms' `RLIM_INFINITY` sentinels, which do not agree: the BSDs
  use the largest positive `int64` and Linux all-bits-set, so reading one with
  the other's value silently yields a bounded ceiling of nine exabytes or of
  -1. Only the syscall and the sentinel constant go unexercised, and a mistake
  there fails loudly at startup rather than quietly later.

- **`ErrLimitDiscoveryFailed` and `LimitDiscoveryError`** for a ceiling that
  could not be READ, wrapping the syscall failure and reachable with
  `errors.As`. Nothing was compared, so it is deliberately neither a verdict on
  the budget nor a shortage of locked memory.

  Resolves #11 (acceptance criterion 2 of #2).

### Changed
- **An enclave whose material has been wiped now reads as DESTROYED even while
  its pages are still held.** `IsAlive` returns false, `Size` returns 0, and
  `Open`, `WithBytes`, `EqualTo` and `EqualToErr` return `ErrEnclaveDestroyed`.

  The case is the failed release: when the wipe succeeded but the `munlock` or
  `munmap` after it was refused, the mapping is deliberately **kept** so
  `Destroy` can be retried. It then read as a perfectly ordinary live enclave —
  `IsAlive` true, a non-zero `Size`, and `Open` handing back **zeroes** from a
  region whose guard pages the release path had already left **read-write**. A
  caller that recovers from `Destroy`'s panic and reads rather than
  re-destroying would derive from an all-zero secret with the guards off, and
  nothing said so.

  "The enclave still reports itself alive, which is the truth" was true of the
  **mapping** and was never true of the **enclave**. The pages stay held for the
  retry either way; only the answers about the material changed.

  **Both branches of the release path are covered.** A frozen enclave loses its
  material to the release `mprotect`; a mutable one — a sized enclave that has not
  been frozen (#6) — loses it to the *early* wipe that runs before any
  syscall that can be refused, so its material is gone even when that `mprotect`
  is the step that fails. The two differ in fact, and the flag follows the fact:
  a genuinely refused wipe still reads as alive, because nothing was destroyed.

### Security

- **A release whose `mprotect` is denied now hands the pages back with a bare
  `munmap` instead of keeping them, and says so.** The wipe that precedes a
  release needs the region writable; for a FROZEN enclave that mprotect is the
  only way in, so a permanent denial — a seccomp filter, a sandbox — left the
  material resident in locked memory for the process lifetime, and retrying
  could not help. The release now falls back to unmapping directly. Nothing
  leaks: the pages were `mlock`'d for their whole life and the kernel zeroes an
  anonymous page before reuse.

  It is reported rather than silent, through the new `ErrReleasedWithoutWipe`
  (as an `UnwipedReleaseError`) and the new **`(*MemoryEnclave) DestroyErr()
  error`** — `Destroy` with its non-fatal report kept rather than discarded,
  the same relationship `EqualToErr` has to `EqualTo`. It is deliberately not
  `ErrEnclaveCorrupted` and does not panic: no memory was corrupted and no
  material outlived its enclave. What it tells an operator is that something in
  the environment is denying `mprotect`, which reaches every other enclave in
  the process. (#38)
- **`Allocator.SetLimit`, `Allocator.ForceLimit` and `Allocator.TransferTo` — a
  budget that can be retuned at runtime and rebalanced between allocators.**
  (#35) Until now `Allocator.limit` was written once in `NewAllocator` and never
  again, so a process whose locked-memory demand moved — a per-tenant seal
  barrier gaining and losing tenants, a container resized under it — could not
  adjust without rebuilding its allocators.

  The two lowering contracts are separate methods because they answer different
  questions. `SetLimit` **refuses** to shrink below the memory already reserved,
  returning a `LimitError` matching the new `ErrBudgetInUse` and changing
  nothing: the reservations belong to live enclaves that only their owners may
  destroy, and no budget decision may invalidate them. `ForceLimit` records a
  ceiling that moved regardless of what is reserved, keeps every live enclave
  working, **returns the over-subscription in bytes** so the caller is told
  rather than left to discover it, and admits nothing further until reservations
  drain beneath the new budget. Zero is a legal runtime budget — quiescing an
  allocator — even though it remains a construction-time error.

- **The admission counter now holds the REMAINING budget rather than the bytes
  used**, which is what makes a moving budget safe. Every operation reduces to
  one signed adjustment of that single word: admitting subtracts, releasing
  adds, raising the budget adds, lowering it subtracts. A budget reduction and
  an allocation therefore compete on exactly the same terms, through the same
  compare-and-swap, and one of them loses — where a limit and a usage counter in
  two separate words would have let a lowering land invisibly between an
  admission's check and its commit, over-committing locked memory the process
  cannot actually get.

  Admission is unchanged in cost and remains lock-free: one atomic word, no
  syscall on refusal. The new mutex serializes budget CHANGES only, and the
  observability getters take it shared so `InUse()` is an exact figure rather
  than a torn pair. It is never taken on the allocation or release path.

  A side benefit: the admission predicate is now `charge > free`, a comparison
  with no arithmetic between the two values, so the overflow class the previous
  `charge > limit-used` form was carefully written to avoid cannot arise at all.
  The DIAGNOSTIC path still subtracts, and `BudgetError.InUse` is now documented
  and tested as never negative: an over-subscribed allocator has a negative
  headroom counter, and a lock-free reader catching it beside a freshly raised
  limit would otherwise compute a byte count that wrapped. A wrapped count is not
  a stale reading but an impossible one, and a consumer graphing it cannot tell
  the difference. Caught by Codex on PR #44.

  `Available()` reports zero rather than a negative remainder while an allocator
  is over-subscribed, and `BudgetError.InUse` may now exceed `BudgetError.Limit`
  — both states are reachable only through `ForceLimit`, and both are what an
  over-subscribed allocator honestly looks like.

- **`Allocator.TransferTo` moves headroom between two allocators as one
  operation.** Doing it as a lowering plus a raise leaves a window in which the
  bytes are in both allocators or in neither, depending on the order; "both"
  lets each side admit against the same locked memory. The transfer debits the
  source first and credits the destination second, so the intermediate state is
  always "in neither" — conservative, recoverable by a retry, and unobservable
  to any other retune since both locks are held across it. The two locks are
  taken in a fixed total order (ascending construction id), which is what makes
  concurrent A→B and B→A transfers impossible to deadlock.

  No parent/child budget hierarchy was introduced; #35 records that as an
  architecture decision for the owner, and direct transfer does not need one.

  None of the three re-checks `RLIMIT_MEMLOCK`, exactly as `NewAllocator` does
  not. An allocator built by `NewAllocatorWithinRLimit` (#43) can be raised back
  above the ceiling that constructor refused, so that check is a startup check
  and does not carry forward; `SetLimit`'s doc comment says so. Applying it to a
  retune would be a behavior decision for the owner rather than a gap to fill
  quietly, and admission fails safe regardless — the kernel refuses the lock and
  the allocation returns `ErrLockedMemoryUnavailable`.


## [v0.4.0-alpha] - 2026-08-26

### Added

- **`WipeAll() (int, error)` — a cooperative shutdown sweep that destroys every
  live enclave, reports how many it could not, and reports whether any of them
  were corrupt.** For an orderly exit: a signal handler, a defer in main. It is
  not a fault handler and nothing calls it for you.

  The two return values are **orthogonal, and neither implies the other**. The
  count is how many enclaves are still holding locked memory; a non-zero value
  is a shutdown-ordering bug in the caller. The error reports detected canary
  corruption and nothing else, matching `ErrEnclaveCorrupted` through
  `errors.Is` exactly as `Destroy`'s panic value does, and naming how many
  enclaves failed.

  A corrupt enclave's pages **are** reclaimed, so it is not "still held" and
  never appears in the count — which is precisely why the corruption needs a
  return value of its own. An earlier revision of this branch returned only the
  count, so a sweep that detected memory corruption reported `0` and looked like
  a clean exit: `Destroy` panics on that same condition because it matters, and
  a sweep must not abort, but non-fatal must not mean invisible either.

  This is the one thing v0.3.0-alpha's removal of memguard left a consumer
  needing. Option B deleted memguard's process-global registry because of what
  memguard did WITH it — purge the whole thing on any mapping failure, then panic
  — while a consumer had been relying on that same registry for a *cooperative*
  exit wipe. After the conversion its exit path silently stopped covering the
  key it was meant to destroy: nothing failed, nothing announced it.

  A cooperative sweep is a different mechanism wearing a similar shape.
  `WipeAll` is called explicitly rather than triggered by a fault, **never
  panics** — a sweep that aborted partway would leave every enclave after the
  failure untouched — and **never waits on a reader**: an enclave being read
  when the sweep reaches it is retried on a later pass, and only one still held
  after every pass is counted, because a shutdown that hangs behind a goroutine
  still reading a key is worse than one that reports what it could not reach.

  The registry is touched on construction, on destruction, and by `WipeAll` — and
  by **nothing on the borrow path**, which is what keeps `purgeMu` from coming
  back. Allocating inside a live borrow still works.

### Changed

- **`WipeAll` waits briefly between retry passes, so the promise it makes about
  momentary readers is actually true.** Without it the retry loop was
  temporally degenerate: all eight passes completed in about 966 **nanoseconds**,
  so "still held after every pass" meant "held for more than roughly a
  microsecond," and a realistic reader — a health probe calling `IsAlive`, a
  `Size`, an `EqualTo` — lost its enclave 20/20 times at every duration from
  20µs to 2ms.

  This is a backoff, not synchronization, and the distinction is the test:
  remove the wait and the sweep is still **correct** — the enclave simply is not
  reclaimed on that call, the count stays honest, and the documented remedy
  still works. A sleep standing in for an ordering guarantee becomes *wrong*
  when removed; that is the pattern this project bans, and this is not it. There
  is also nothing to wait on: the party being waited for is another goroutine's
  read lock, and `sync.RWMutex` exposes no "notify when free."

  Cost is milliseconds at shutdown, and only when something is genuinely still
  held. Stated as measured rather than as arithmetic: nominally 1.4ms, measured
  at **7.5ms** against a held enclave, because short sleeps overshoot.

- **`WipeAll`'s documentation no longer attributes a non-zero count solely to
  caller ordering.** A read that simply outlasts the retry budget produces the
  same number, so the count now reads as "these were still in use" rather than
  as a diagnosis — and it says plainly that `WipeAll` belongs to the **program
  that owns the process**, never to a library, since it destroys enclaves
  belonging to subsystems a library knows nothing about. Two independent
  consumers reached that conclusion on their own and declined to call it; an API
  two callers separately avoid is inviting the mistake.

- **An enclave is published to the shutdown ledger as the LAST step of its
  construction**, after every field a sweep reads has been set. `Allocator.New`
  and `Allocator.NewSized` install the reservation callback and then register;
  the constructors no longer register on their behalf.

  Registering inside the constructor put an allocator-backed enclave on the
  ledger while `Allocator.New` had not yet assigned its `release` callback. A
  `WipeAll` landing in that window read the field while it was being written — a
  data race — and destroyed the enclave with `release` still nil, handing the
  pages back to the kernel while the budget kept the charge. In the
  `WipeAll`-at-exit pattern, where the sweep is the destroyer, nothing ever
  returns that charge: an `Allocator` that sweeps and keeps running loses
  admission capacity permanently. Measured on the defective shape, 34–52 MiB of
  a 256 MiB budget was stranded per run.

  No API change; `WipeAll` and both allocator constructors behave as documented.

- **A momentary reader no longer costs an enclave its sweep.** `WipeAll` retries
  an enclave it could not lock on its next pass, instead of writing it off after
  one lost race.

  `tryReleaseMapping` takes the WRITE lock without waiting, so it loses to any
  concurrent reader — `IsAlive`, `Size`, `EqualTo`, a health probe polling an
  enclave during shutdown — not merely to a long `WithBytes` borrow. The sweep
  marked every enclave as seen when it built a pass's batch, *before* trying to
  release it, so one lost microsecond took that enclave out of the sweep
  permanently: no later pass reconsidered it, the process exited with the
  material still mapped and locked, and the returned count blamed the caller's
  shutdown ordering. That is the outcome `WipeAll` exists to prevent, reached
  through the most ordinary concurrent operation there is.

  Termination never depended on the seen-set — `maxSweepPasses` is the bound —
  so it is gone. A genuinely long borrow still outlives every pass and is
  skipped and counted, which remains correct: memory being actively read must
  not be unmapped underneath the reader.

- `tryReleaseMapping` now returns `(released bool, err error)` rather than
  `(error, bool)`, putting the error last as the conventions require.

### Documentation

- **`WipeAll` is documented in the API surface**, in both the README table and
  the package doc, where it was missing entirely.
- **The README's "enclaves are destroyed when their owner destroys them and at
  no other time" is corrected.** It became false the moment a global sweep
  existed. What remains true — and is what the sentence was protecting — is that
  nothing destroys an enclave in reaction to a *fault*.
- **`Open` names `WipeAll` as a second concurrent destroyer.** A retained `Open`
  slice segfaults if a shutdown sweep runs while the caller still holds it, and
  only this enclave's own `Destroy` was mentioned before.
- **The constructors document that a successful return can hand back an
  already-destroyed enclave** when `WipeAll` ran between publication and return.
- **The registry design note states its two costs plainly:** `registryMu`
  serializes construction and destruction process-wide (it is not `purgeMu` — it
  never touches the borrow path and is never held across a syscall or an enclave
  lock), and an enclave whose release keeps failing is retained for the process
  lifetime by design, so a later sweep can retry it.

### Tests

- **The never-panics guarantee is now pinned rather than merely documented.**
  `WipeAll`'s most prominent promise — that it does not panic, including on an
  enclave whose canary fails — had no test. A corrupt canary is now seeded into
  a batch and the whole batch is checked: no panic, every enclave wiped, the
  sweep not aborted at the failure, the corrupt enclave's reservation returned
  (a detected corruption still counts as released), and the corruption
  **reported** through the error rather than swallowed.
- **The concurrent-construction test was rebuilt to be affordable in CI.** Its
  first two versions needed a large payload (1 MiB, then 512 KiB) to widen the
  window they race for, and a sweeper that spun without yielding to sample it
  often. Both worked locally — including pinned to a single CPU — and both blew
  the test's own drain bound on the build runner, twice.

  The payload was the expensive half: under `-race`, hundreds of megabytes of
  mlock churn in a memory-capped container is a different order of problem from
  slow CPU. The width also turned out to be unnecessary — race detection needs
  the window ENTERED, not held open, and a one-page payload hits it just as
  reliably (8/8 against the defective shape) for 1/128th of the memory. The test
  now costs hundredths of a second on every machine measured.

  The strength that bought moved to the race detector, which is the reliable
  oracle for this defect and is what CI runs; the budget assertion is kept as a
  weaker second signal that needs no detector, and the doc comment says so
  rather than claiming two equal oracles. The "a live successful return is
  usable" check moved to a quiescent phase, because it is a property of
  construction rather than of the race — asserted against a live sweeper it
  failed whenever the sweeper won everything, which on one CPU was 99 times in
  100.
- **The failed-release path is pinned.** An enclave whose release fails for a
  reason that is not corruption keeps BOTH its Allocator charge and its ledger
  entry. Neither was held by any test. Refunding unconditionally would hand the
  budget back while the kernel still holds the pages, so the allocator
  over-admits against a real `RLIMIT_MEMLOCK`; deregistering would make
  `WipeAll` return **zero while the material is still mapped and locked**, and
  no later sweep could ever find it — the same class as the tallied-count
  fail-open. The shipped code was correct on both; nothing held it correct.
- **The corruption contract is pinned in both directions.** One test requires
  the error to name how many enclaves were corrupt; a control requires a clean
  sweep to report `nil`, without which both would pass against an
  implementation that reported corruption unconditionally. Every other test in
  the package now routes its sweep through a helper that fails on an unexpected
  corruption report, so the whole suite doubles as that control.

## [v0.3.0-alpha] - 2026-08-26

### Changed

- **go-enclave maps its own memory.** The backing store is no longer a memguard
  `LockedBuffer`; the package allocates, locks, guards, wipes and releases pages
  through `memcall` directly — the layer memguard itself uses.

  The layout is deliberately unchanged: an mlock'd inner region with the data
  flush against an inaccessible postguard, a random canary in the slack ahead of
  it, a second guard page in front, wipe-and-verify on release. What changed is
  the FAILURE POLICY, which could not be changed from outside memguard. memguard
  registers every buffer in a process-global list and answers any mapping failure
  with `core.Panic`: `Purge()` — destroying and UNMAPPING every live buffer in
  the process — and then a panic. go-enclave converted that panic into a typed
  error from v0.1.0-alpha, but a `recover` cannot undo a purge that already ran,
  so it also needed `purgeMu`, a process-wide lock serializing every allocation
  against every borrow.

- **`purgeMu` is gone, and with it the nested-allocation deadlock.** Allocating,
  borrowing or destroying an enclave from inside another enclave's live borrow
  now works. It previously deadlocked: allocation took the lock exclusively,
  borrows took it shared, and Go's `RWMutex` blocks new readers once a writer
  queues. That blocked an ordinary shape outright — handing borrowed key
  material to an injected interface whose implementations allocate protected
  memory of their own — because the three ways of writing the code were
  deadlock, an unprotected heap copy, or an unsynchronized read.

- **An allocation failure no longer damages unrelated enclaves.** Exhausting
  `RLIMIT_MEMLOCK` fails exactly the allocation that reached the ceiling. An
  enclave is destroyed when its owner destroys it and at no other time, so
  `ErrEnclaveDestroyed` can no longer appear spontaneously on an enclave the
  caller still holds.

- **A failed mapping releases everything it took.** Where memguard aborts and
  never unwinds, this returns an error — so the cleanup is real code, verified
  against `VmLck` and the process's VMA count over 256 induced failures.

- **The material is destroyed before any syscall that could be refused.**
  `mprotect` can be denied — a seccomp filter is the realistic case — and the
  release path used to make the region writable first and wipe afterwards, so a
  refusal returned an error having wiped nothing and left the secret resident on
  locked pages. While the inner region is writable, which it is unless a freeze
  succeeded, the material needs no syscall to destroy; it is now destroyed
  first, so the worst a refusal can cost is an empty mapping that could not be
  handed back.

- **A release that could not unmap keeps its handle.** If the region cannot be
  made writable — so it was never wiped — or cannot be unlocked or unmapped, the
  mapping is left intact and the `Allocator` reservation is NOT returned.
  Clearing the fields regardless would strand memory that is still resident,
  possibly still locked and possibly still holding material, with no reference
  left to retry through, while the budget reported those bytes as available. A
  caller that recovers from the panic can call `Destroy` again to retry.

- The `Allocator` is unchanged in shape but its rationale is narrower and
  honest: it bounds one path's consumption so an untrusted source cannot starve
  the rest of the process. It never protected against collateral purges, and
  there are no longer any to protect against.

### Added

- `CoreDumpsDisabled()` reports whether lowering `RLIMIT_CORE` at import
  succeeded. The package documented core dumps as disabled while discarding the
  result, which is a guarantee the code did not enforce and a control callers had
  no API to assert. It is best effort by nature, so it is now reported rather
  than promised — and every enclave's pages are separately marked
  `MADV_DONTDUMP` as they are locked, which **is** verified and fails the
  allocation if refused. memcall attempts the same madvise and discards its
  result, so this is the first core-dump control here that is actually checked.

- `ErrEnclaveCorrupted`, reported when the canary does not verify on release.
  `Destroy` wipes and releases everything it holds, returns the `Allocator`
  reservation, and then panics with it — see its documentation for why detected
  memory corruption is the one condition this package does not hand back as an
  error.

### Removed

- The `github.com/awnumar/memguard` dependency, and with it `golang.org/x/crypto`
  — go-enclave never called memguard's `Enclave`/`Seal` paths, but their NaCl
  secretbox sat in the build graph of every consumer, and x/crypto is where the
  ten HIGH CVEs cleared in v0.2.0-alpha came from. The module now requires
  `memcall` and `golang.org/x/sys` and nothing else.

## [v0.2.1-alpha] - 2026-08-26

### Fixed

- **`Allocator` admitted against the wrong unit.** The budget counted requested
  BYTES while the kernel charges locked PAGES, so a budget sized below
  `RLIMIT_MEMLOCK` was not actually bounded by it — the comparison the type
  exists to make could not be made. Measured against `/proc/self/status` VmLck
  on a 4 KiB-page host: a 32-byte enclave locks 4096 bytes, a **128x**
  undercount, and 200 of them charged 6400 bytes against a budget while locking
  819200. Reservations are now charged, reported and released in locked bytes,
  page-rounded as the kernel charges them.

- **A size too large to MAP reached memguard and purged the process.** memguard
  lays out the data region plus two guard pages using `int` arithmetic
  (`core.NewBuffer` asks `memcall.Alloc` for `2*pageSize + roundToPageSize(size)`),
  so past a certain size that arithmetic overflows, `mmap` refuses the nonsense
  length, and `core.Panic` destroys every live locked buffer in the process.
  Measured on v0.2.0-alpha with `n = MaxInt64-pageSize`: admission passed, the
  request reached memguard, and an unrelated canary enclave came back dead. Both
  construction paths are now gated — `Allocator.NewSized` through admission and
  `NewMemoryEnclaveSized`, which has no allocator in front of it at all.

### Added

- `LockedSize(n int) int64` — the locked memory an enclave of n bytes actually
  consumes, so a caller can size a budget instead of guessing. Returns int64 to
  match `NewAllocator`'s budget, so sizing one needs no conversion. Guard pages are
  not part of it: they are mapped PROT_NONE and never mlock'd, verified against
  the kernel's accounting rather than inferred from the mapping code.

### Changed

- `ErrInvalidSize` now reports two conditions rather than one: a non-positive
  size, and a size too large for memguard to map. Its message changed to match.
  A larger `Allocator` budget helps with neither, which is why they are not
  `ErrBudgetExhausted`.
- `Limit`, `InUse`, `Available` and `BudgetError.Requested` are documented as
  **locked bytes**, comparable to `RLIMIT_MEMLOCK`. Existing budgets therefore
  admit far fewer enclaves — which is the fix, not a regression: they admitted
  more before only by mismeasuring. A budget below one page constructs and then
  admits nothing, refusing with figures that show why.

## [v0.2.0-alpha] - 2026-08-26

### Added

- `NewMemoryEnclaveSized(n int)` and `Allocator.NewSized(n int)`: locked, zeroed
  memory of `n` bytes that the caller fills IN PLACE through the existing
  `WithBytes` borrow, so generated material — a drawn key, a derived wrapping
  key, a Shamir share — never exists on the ordinary heap, not even transiently.
  Until now the whole construction surface took existing bytes, which forced
  callers into the `make` + generate + move shape the wipe cannot fully undo.
- `ErrInvalidSize` for a non-positive size, mirroring `ErrInvalidBudget`.
  `Allocator.NewSized` refuses it at the admission gate, before memguard is
  entered.

### Changed

- `Allocator`'s admission gate is now a single `reserve` step shared by `New` and
  `NewSized`, and it refuses a non-positive reservation outright — the byte
  counter can no longer be driven below zero, which would have let a concurrent
  caller admit against an inflated budget.
- The admission predicate compares the request against the remaining budget
  instead of testing `used + n` against the limit. The addition overflows int64
  for a large enough request and wraps negative, which passed the budget test and
  admitted an allocation the budget could not cover — a fail-open into memguard,
  reachable through `NewSized` because it takes its size from the caller as a
  plain int rather than as the length of an already-allocated slice.
- Documented the one property that separates the two construction paths after
  construction: memguard freezes the pages of an enclave built from existing
  material, while a sized enclave's pages stay writable for its lifetime. `Open`
  and the package documentation previously said a write always faults.

### Security

- Bumped the indirect `golang.org/x/crypto` from v0.41.0 to v0.52.0, clearing ten
  HIGH CVEs (CVE-2025-47913, CVE-2026-39828/-39829/-39830/-39831/-39832/-39835,
  CVE-2026-42508, CVE-2026-46595, CVE-2026-46597). No go-enclave code imports the
  module — it arrives via memguard — so `govulncheck` reported them only as
  present-but-uncalled; `trivy` is module-level and does flag them.
- Added a tracked, intentionally empty `.trivyignore`, and pointed the `Makefile`'s
  `trivy` target at it. The nightly Trivy job passes `--ignorefile .trivyignore`,
  and trivy treats a missing ignore file as a FATAL flag error rather than as an
  empty list — so that job had never scanned this repository, and the CVEs above
  were behind the error it died on.

## [v0.1.0-alpha] - 2026-08-23

### Added

- Initial release. `MemoryEnclave`, a region of locked, zeroized memory for
  holding sensitive material for its whole lifetime in the process. Extracted
  from an object-storage library that had grown its own copy, so that libraries
  handling key material can share one implementation instead of each rolling
  their own.
- Error-returning locked-memory handling: an mlock failure yields a typed
  `LockedMemoryError` / `ErrLockedMemoryUnavailable` instead of memguard's
  process-wide `Purge` + panic.
- The `WithBytes` borrow window and process-wide `purgeMu` coordination, so an
  in-flight borrow survives a purge triggered elsewhere in the process.
- Admission control: `Allocator`, a lock-free bounded allocator with a typed
  `ErrBudgetExhausted` / `BudgetError`, so callers can cap unauthenticated
  locked-memory allocation below the RLIMIT_MEMLOCK ceiling that triggers a
  purge. Reservations are released on `Destroy`.

[v0.3.0-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.3.0-alpha
[v0.2.1-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.2.1-alpha
[v0.2.0-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.2.0-alpha
[v0.1.0-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.1.0-alpha

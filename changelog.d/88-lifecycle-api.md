### Changed — BREAKING:

- **`MemoryEnclave.Destroy` returns an `error`, and `DestroyErr` is gone**
  (#88). `Destroy() error` has `DestroyErr`'s semantics. It returns `nil`
  for a successful release, for a nil enclave and for every call after a
  successful release. It returns `ErrReleasedWithoutWipe` when a denied
  `mprotect` forced a bare unmap, and `ErrLockedMemoryUnavailable` when the
  kernel refused the release. A refused release keeps the mapping, the
  `WipeAll` ledger entry and the `Allocator` reservation. Calling `Destroy`
  again retries it, and returns the refusal again for as long as the kernel
  keeps refusing. Detected canary corruption still panics with a
  value matching `ErrEnclaveCorrupted`. It is the package's one deliberate
  panic and is now documented as the single exception to "library code
  does not panic", with its security rationale: a returned error is
  dropped by `defer e.Destroy()`, and a secrets process whose memory was
  written by something that did not own it must not carry on. Migration:
  `e.DestroyErr()` becomes `e.Destroy()`. A bare `e.Destroy()` or
  `defer e.Destroy()` still compiles and still discards the report.
- **`WipeAll` takes a `context.Context` and waits for borrows instead of
  sleeping** (#88). `WipeAll(ctx) (int, error)` replaces the fixed 200µs
  backoff between at most eight passes. An enclave being read when the
  sweep reaches it is waited for, and the end of the borrow wakes the sweep
  (any `WithBytes`, `Open`, `OpenString`, `EqualTo`, `Size`, `IsAlive`,
  `Freeze` or `Destroy` holding its lock). `ctx` bounds every wait and
  nothing else: the wait for a borrow, immediate retries of a contended
  lock, and the wait to be admitted while another sweep runs. When it ends
  during a sweep, a still-borrowed enclave is left mapped and counted. An
  already-done or nil `ctx` that is admitted still reclaims everything not
  currently held and only declines to wait. Only one sweep runs at a time.
  A call whose `ctx` ends before it is admitted, or whose `ctx` is nil while
  another sweep runs, sweeps nothing and returns the current ledger count
  with the new sentinel `ErrSweepInProgress`. A deadline is never held
  hostage by a sweep running under `context.Background()`. Under
  `context.Background()` the sweep, and a second `Background` caller queued
  behind it, waits as long as the borrows it owes take, so give a shutdown
  sweep a deadline, taken at shutdown. Constructors racing the sweep are
  reclaimed when reached, but they can no longer keep it running: only
  entries present at the first pass are waited for or earn another pass.
  A goroutine that constructs forever cannot stop a `context.Background()`
  sweep from finishing. Migration: `WipeAll()` becomes `WipeAll(ctx)`.
- **The findings of an admitted `WipeAll` are a typed
  `*SweepError{Corrupt, Unwiped int}`** (#88), replacing a join of
  `fmt.Errorf` values with the same text. A call that was never admitted
  returns `ErrSweepInProgress` instead. That is an admission result, not a
  finding about memory.
  `errors.Is` still matches `ErrEnclaveCorrupted` when `Corrupt > 0` and
  `ErrReleasedWithoutWipe` when `Unwiped > 0`, and `errors.As` now exposes
  the counts. A context ending during an admitted sweep is not an error,
  and the count already reports what it left behind.
- **A borrow costs two atomic adds and one atomic load more** (#88). This
  is how a waiting sweep hears a borrow end without relying on what a
  failed `TryLock` cannot promise. No lock and no allocation were added to
  the borrow path. New benchmarks (`BenchmarkBorrow*`,
  `BenchmarkIsAliveParallel`) measure the cost.

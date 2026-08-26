# Changelog

All notable changes to go-enclave are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [v0.3.0-alpha] - 2026-08-26

### Changed

- **go-enclave maps its own memory.** The backing store is no longer a memguard
  `LockedBuffer`; the package allocates, locks, guards, wipes and releases pages
  through `memcall` directly — the layer memguard itself uses. Owner ruling on
  issue #2, 2026-08-26.

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
  queues. That blocked go-qrdb #74/#145 outright — the three ways of writing the
  code were deadlock, an unprotected heap copy, or an unsynchronized read.

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
  page-rounded as the kernel charges them (go-enclave #7).

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
  consumers into the `make` + generate + move shape the wipe cannot fully undo
  (go-enclave #1, filed for go-qrdb #114).
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
  were behind the error it died on (go-enclave #4).

## [v0.1.0-alpha] - 2026-08-23

### Added

- Initial release. `MemoryEnclave`, a region of locked, zeroized memory for
  holding sensitive material for its whole lifetime in the process, extracted
  from `go-objstore/pkg/enclave` (owner ruling 2026-08-23; go-objstore #29) so
  that every Layer 0–3 library in the portfolio can import it.
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

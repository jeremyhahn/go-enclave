# Changelog

All notable changes to go-enclave are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
  match the budget type and because on a 32-bit platform the cost of a large
  enclave exceeds what an int can hold. Guard pages are
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

[v0.2.0-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.2.0-alpha
[v0.1.0-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.1.0-alpha

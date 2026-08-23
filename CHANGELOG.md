# Changelog

All notable changes to go-enclave are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and the project adheres to
[Semantic Versioning](https://semver.org/).

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

[v0.1.0-alpha]: http://198.51.100.91:3001/jeremyhahn/go-enclave/releases/tag/v0.1.0-alpha

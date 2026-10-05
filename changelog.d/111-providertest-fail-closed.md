### Changed — BREAKING: `providertest` fails closed when its residue sweep cannot measure

- **`providertest` fails closed when its residue sweep cannot
  measure** (#111). Off Linux, without locked memory, or with a blind control,
  `TestProvider` now returns an error matching the new `ErrNotMeasured`
  (`*NotMeasuredError`) instead of logging and returning `nil`. Set
  `Config.SkipResidueSweep` with a reason to accept the gap.

### Changed — BREAKING: every `providertest` error message starts with `providertest:`

- **every `providertest` error message starts with `providertest:`**
  (#111), including `PropertyError`.

### Fixed

- **The residue sweep sees keys kept outside anonymous memory** (#111). It now
  reads memfd, `/dev/shm`, SysV, `/dev/zero`, unlinked and every writable
  file-backed mapping; only read-only views of on-disk files are skipped.
- **The sweep no longer panics on a 32-bit target with a mapping wider than
  `math.MaxInt32`** (#111); the read length is bounded before it is converted.
- **The ended-context `UnsealRoot` check wipes its destinations** (#111) once
  the call returns, or from the abandoned call's goroutine once the provider
  returns, so root material a misbehaving provider wrote there does not linger
  on the heap.

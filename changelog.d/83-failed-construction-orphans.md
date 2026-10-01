### Fixed

- **`WipeAll` reclaims the pages of a construction whose cleanup was
  refused** (#83). When a constructor failed after mapping its pages, and
  the rollback was refused too (a freeze refused by `mprotect`, then a
  release refused by `mprotect` and the bare `munmap`), it returned an error
  and dropped the only handle to pages the kernel still held. No sweep could
  reach them, even after the refusal lifted, and an `Allocator` charge kept
  for still-locked pages stayed charged for the process lifetime. Such
  mappings are now kept on an internal ledger that every `WipeAll` pass
  retries. They are included in its count while they are still mapped. The
  sweep that releases them returns any charge kept for them, exactly once.
  A mapping abandoned before any material was copied in also retries the
  bare `munmap` on every sweep when `memcall.Free` is refused, as its
  rollback did, so a bare unmap refused only transiently does not strand it.
  Likewise a refused `munlock` no longer stops its retry before the unmap,
  which takes the lock with it, so a locked orphan is reclaimed — and its
  kept charge refunded once — as soon as unmapping is possible again.
  `WipeAll`'s documentation now also states that its error reports
  `ErrReleasedWithoutWipe` alongside `ErrEnclaveCorrupted`, which it already
  did.

### Fixed

- **A retried release no longer unlocks pages it already unlocked** (#83).
  When a release's `munlock` succeeded and its `munmap` was refused, every
  retry through `DestroyErr` or `WipeAll` called the unlock again. Linux
  accepts that, but Windows' `VirtualUnlock` refuses pages that are not
  locked, so each retry failed at the unlock without reaching the `munmap`.
  The mapping, and any `Allocator` reservation behind it, was then held for
  the process lifetime. A mapping now records a successful unlock, a retry
  goes straight to the `munmap`, and a held release reports whether the
  pages are still locked from that same record.

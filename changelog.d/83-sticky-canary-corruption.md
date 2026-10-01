### Fixed

- **A detected canary corruption is no longer lost when the release after it
  is refused** (#83). Verification wipes the guard pages and the canary.
  When the `munlock` or `munmap` after it failed, the release returned only
  that failure and kept the mapping. The retry then compared zeroes with
  zeroes and reported a clean release. The corruption flag is now sticky and
  verification runs once per mapping. An attempt that both detects
  corruption and is refused returns both, joined, so `Destroy` still panics
  with `ErrEnclaveCorrupted`, and the retry that releases the pages reports
  it again. The joined error is never counted as released: the handle,
  ledger entry and `Allocator` reservation are all kept until the pages
  actually go back.

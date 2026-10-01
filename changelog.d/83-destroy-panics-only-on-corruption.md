### Fixed

- **`Destroy` no longer panics when the kernel refuses a release** (#83).
  `DestroyErr` panicked on every error except `ErrReleasedWithoutWipe`. That
  included a plain refused `munlock` or `munmap` (`ENOMEM` at
  `vm.max_map_count`, for example), although the documentation says only a
  failed canary panics. Detected corruption is now the only panic. A refused
  release is returned by `DestroyErr` as `ErrLockedMemoryUnavailable`, and
  `Destroy` discards it. In both cases the enclave keeps its mapping for a
  retry, stays on the `WipeAll` ledger and keeps its `Allocator`
  reservation, as before. It reports itself destroyed once its material is
  wiped.

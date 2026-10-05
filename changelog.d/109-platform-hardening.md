### Added

- **Enclave pages are excluded from forked children on Linux** (#109). Every
  mapping is marked `MADV_DONTFORK`, so a `fork(2)` child has no mapping there
  and touching an enclave faults instead of reading the material. A refused
  `madvise` fails the allocation with `ErrLockedMemoryUnavailable`, like the
  core-dump exclusion; other platforms apply nothing (x/sys exposes no
  `minherit`).
- **`HardenProcess()`, opt-in process hardening for binaries** (#109). On Linux
  it sets `PR_SET_DUMPABLE` to 0 and reports what it verified in
  `ProcessHardening`. That blocks core dumps and same-uid `ptrace`, and breaks
  same-uid debuggers; elsewhere it returns `ErrProcessHardeningUnsupported`.
  The package never calls it.

### Fixed

- **`RLIMIT_MEMLOCK` is reported enforced inside user namespaces** (#109).
  `CAP_IPC_LOCK` only lifts the limit in the initial user namespace, so root of
  a rootless container used to get `LimitNotEnforced` and then a late `mlock`
  `ENOMEM` instead of `ErrBudgetExceedsRLimit`. An unreadable
  `/proc/self/uid_map` now counts as enforced.
- **`madvise` failures are `*os.SyscallError`s** (#109), naming the call like
  every other system call the package makes.

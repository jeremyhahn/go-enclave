### Changed

- **The unit suite has no skip guards** (#90). Every former `t.Skip` was
  resolved by what it was hiding: allocation and ledger preconditions and
  vacuity guards ("the measurement observed nothing", "no fault was
  injected") are failures; environment capabilities the suite relies on are
  guaranteed and fail loudly when absent; platform-specific tests are
  build-tagged files. Test files are consolidated so each maps to the source
  file it covers.
- **The suite states its locked-memory requirement**: both packages' `TestMain`
  refuse to run under a soft `RLIMIT_MEMLOCK` below 2 MiB (measured need about
  1 MiB) with one actionable message, instead of failing allocation by
  allocation. An unlimited limit satisfies it; so does `CAP_IPC_LOCK` when the
  hard limit also reaches 2 MiB, because the fault-injection tests drop the
  capability and then raise the soft limit to at most the hard one.
- **`make coverage` enforces the 90% floor per package**, not only on the
  statement-weighted total that let `providertest` sit at 84.6%;
  `providertest` is now above the floor.

### Fixed

- **No test copies enclave contents out of a borrow into ordinary memory**
  (security-review §6); assertions happen inside the borrow.
- **`providertest` no longer copies a provider's root onto the ordinary heap**
  (#90). Against a real device `UnsealRoot` returns that device's actual root
  key; the root checks now receive it, snapshot it and compare it only in
  locked enclaves held for each check's observation windows, and destroy them
  afterwards.

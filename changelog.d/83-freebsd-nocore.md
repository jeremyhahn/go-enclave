### Changed

- **FreeBSD enclaves are now verifiably excluded from core dumps with
  `MADV_NOCORE`** (#83). The per-mapping exclusion was wired only on Linux,
  and the documentation said no other platform had one; FreeBSD does.
  memcall already issued the same `madvise` inside its `Lock` but discarded
  the result. go-enclave now issues it itself and checks it, so on FreeBSD,
  as on Linux, a refused exclusion fails the allocation with
  `ErrLockedMemoryUnavailable` instead of returning an enclave whose pages
  could reach a core file. Other non-Linux platforms are unchanged.

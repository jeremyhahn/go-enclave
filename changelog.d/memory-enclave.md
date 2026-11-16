### Added

- **memory-enclave**: an integration test (`TestMemoryEnclave_ImportChangesNoProcessState`) proves a fresh process that links go-enclave but calls nothing in it stays dumpable, has nothing locked (`VmLck` 0), keeps the devcontainer's `RLIMIT_MEMLOCK`, and maps no `secretmem` area, all read back from the kernel.

### Fixed

- **memory-enclave**: the residue sweep behind the `providertest` and `backendtest` residue checks now skips a thread-stack guard page (glibc on Linux 6.13 and later) instead of failing with an unreadable mapping, but only on a kernel whose `/proc/self/pagemap` reports `PM_GUARD_REGION` (Linux 6.15 or later, or a backport) and only when the process can read its pagemap. Elsewhere such a page, like every other unreadable page, still fails the sweep closed.

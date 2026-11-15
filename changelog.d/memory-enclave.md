### Added

- **memory-enclave**: an integration test (`TestMemoryEnclave_ImportChangesNoProcessState`) proves a fresh process that links go-enclave but calls nothing in it stays dumpable, has nothing locked (`VmLck` 0), keeps the devcontainer's `RLIMIT_MEMLOCK`, and maps no `secretmem` area, all read back from the kernel.

### Fixed

- **memory-enclave**: the residue sweep behind the `providertest` and `backendtest` residue checks no longer fails with an unreadable mapping when a thread stack carries a kernel guard region (glibc on Linux 6.13 and later); it skips only pages the kernel reports as guard regions and still fails on every other unreadable page.

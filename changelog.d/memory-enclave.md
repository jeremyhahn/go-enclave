### Added

- Integration test `TestMemoryEnclave_ImportChangesNoProcessState`: a fresh process that links go-enclave but calls nothing in it stays dumpable, has nothing locked (`VmLck` 0), keeps the devcontainer's `RLIMIT_MEMLOCK`, and maps no `secretmem` area, all read back from the kernel.

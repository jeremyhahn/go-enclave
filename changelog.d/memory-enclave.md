### Added

- **memory-enclave**: an integration test (`TestMemoryEnclave_ImportChangesNoProcessState`) proves a fresh process that links go-enclave but calls nothing in it stays dumpable, has nothing locked (`VmLck` 0), keeps the devcontainer's `RLIMIT_MEMLOCK`, and maps no `secretmem` area, all read back from the kernel.
- **memory-enclave**: Fuzz targets for the residue scanner: `FuzzParseMapsHeader` checks the maps-line parser against an independent reading of the header, and `FuzzFind` walks synthetic maps text over an image at a fixed base, failing on any read outside a swept range and on any hit that differs from the needle's true placement (#366).

### Fixed

- **memory-enclave**: `memscan.ParseMapsHeader` no longer accepts a header whose low bound is above its high bound (#366).

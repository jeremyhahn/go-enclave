### Changed

- **The memory scan fails closed** (#146). `internal/memscan` returns `ErrUnreadableMapping` (as `*UnreadableMappingError`, naming the mapping) when a mapping it must read cannot be read in full, and `ErrEmptySweep` when it read no mapping at all; neither passes as a clean sweep. Only the kernel's `[vvar]`, `[vvar_vclock]` and `[vsyscall]` are excused.
- **The enclave integration suite gates `providertest` coverage** (#146). `INTEGRATION_COVERPKG_enclave` names `providertest` next to the root package, each held to `COVERAGE_THRESHOLD`.

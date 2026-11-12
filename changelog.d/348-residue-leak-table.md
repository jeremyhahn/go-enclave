### Added

- `providertest` is held to each way a provider can keep a key past `Unprotect`: a Linux test table plants a retained copy in a package-level slice, a map value, a `sync.Pool`, a buffered channel, a parked goroutine's stack, a kept `string`, anonymous private and shared mappings, an undestroyed second memory enclave, and either half of the key, and requires exactly the residue finding for each; the clean provider passes (#348).

### Fixed

- `providertest`'s residue sweep now also searches for each half of the key, so a provider that keeps only the first or the last 16 bytes of a recovered key is reported; it looked only for the whole key before (#348).

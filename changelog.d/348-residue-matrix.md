### Added

- `providertest` is held to each way a provider can keep a key past `Unprotect`: a Linux test table plants it in a package-level slice, a map value, a `sync.Pool`, a buffered channel, a parked goroutine's stack, a kept `string`, anonymous private and shared mappings, an undestroyed second memory enclave, and half the key, and requires the residue finding for each; the clean provider passes (#348).

### Fixed

- `providertest`'s residue check now fails a provider that keeps only the first or the last half of the key; it looked only for the whole key before (#348).

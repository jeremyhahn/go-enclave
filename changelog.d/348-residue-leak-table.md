### Fixed

- `providertest`'s residue sweep now also searches for each half of the key, so a provider that keeps only the first or the last 16 bytes of a recovered key is reported; a test plants a retained copy in a package-level slice, a map value, a `sync.Pool`, a channel buffer, a parked goroutine's stack, a string, an anonymous private or shared mapping and a second memory enclave, and checks the suite reports each one (#348).

### Fixed

- `backends/armtrustzone` now pins every buffer whose address it passes to the TEE driver, so a goroutine stack move can no longer leave the kernel with a stale address (#206).
- `backends/armtrustzone` callers waiting for the TEE session now leave with their context's error as soon as the context is done, instead of waiting for another device call to finish (#206).

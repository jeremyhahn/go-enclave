### Added

- **The `mac-secure-enclave` backend's module, `backends/macse`, begins** (#192): typed errors (`ErrSecureEnclaveUnavailable`, `ErrSecureEnclaveOperation`, `ErrInvalidSignInput`, `*SecurityError` naming the failing step and its `OSStatus`, `*PlatformError`), the probe (one transient key, one signature, verified in Go) and `New`, `Name` and `Rank` 2. It has no Security framework binding yet, so on every platform `New` and `Probe` refuse with `ErrSecureEnclaveUnavailable`; the darwin binding follows. Nothing changes for Go callers of the root module.

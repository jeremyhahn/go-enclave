### Fixed

- **`backendtest` reused one AEAD nonce for every `Seal`** (#152), across concurrent calls and between checks, against the `cipher.AEAD` contract, so a backend that refuses a reused nonce failed. Every `Seal` now draws a fresh random nonce and opens with the same one.
- **`backendtest` passed a `Destroy` racing concurrent operations that returned nil and left the handle alive** (#152). The handle must now be dead after the race whatever `Destroy` returned, and a handle a capability check or the `Importer` check created must be dead after its cleanup `Destroy`.

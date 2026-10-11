### Fixed

- **`backendtest` failed every AES-256-GCM `Importer` under FIPS 140-only mode** (#154): its import check ran `cipher.NewGCM` under a caller-chosen nonce, which `GODEBUG=fips140=only` refuses. There it now checks the handle's ciphertext body against AES-CTR from GCM's second counter block. The test fakes no longer use GCM under a caller-chosen nonce or RSA keys under 2048 bits in that mode.

### Changed

- **`make test-fips` gates every PR** (#154): the FIPS 140-3 strict unit run moved from the nightly workflow to CI, and the CI Gate requires it.

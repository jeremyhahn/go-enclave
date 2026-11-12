### Added

- `backends/armtrustzone` tests `Backend.Close` over the fake TEE on both driver kinds: a second `Close` and later `Probe` and `Random` calls return `ErrBackendClosed`, `Close` waits out a `Random` in flight until it is canceled, and a closed backend leaves no device, session or shared memory open (#347).
- `backends/armtrustzone` tests `Backend.Random` over the fake TEE on both driver kinds: one chunk, an exact multiple of the chunk size and one byte over each land chunk by chunk at their offsets, and a TA error, an INVOKE ioctl error or a cancel on the first, a middle or the last chunk returns no handle and leaves no shared memory live (#347).

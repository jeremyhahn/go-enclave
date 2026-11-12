### Added

- `backends/armtrustzone` tests `Backend.Close` over the fake TEE on both driver kinds: a second `Close` and later `Probe` and `Random` calls return `ErrBackendClosed`, `Close` waits out a `Random` in flight until it is canceled, and a closed backend leaves no device, session or shared memory open (#347).

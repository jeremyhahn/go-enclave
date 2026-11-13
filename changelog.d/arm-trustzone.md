### Added

- **arm-trustzone**: Tests cover `Backend.Close` over the fake TEE on both driver kinds, so a closed backend returns `ErrBackendClosed`, waits out a `Random` in flight and leaves no device, session or shared memory open. ([#347](https://github.com/jeremyhahn/go-enclave/issues/347))
- **arm-trustzone**: Tests cover `Backend.Random` over the fake TEE on both driver kinds, chunk by chunk, so a TA error, an INVOKE ioctl error or a cancel on any chunk returns no handle and leaves no shared memory live. ([#347](https://github.com/jeremyhahn/go-enclave/issues/347))

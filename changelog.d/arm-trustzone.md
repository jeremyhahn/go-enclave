### Added

- **arm-trustzone**: Tests cover `Backend.Close` over the fake TEE on both driver kinds, so a closed backend returns `ErrBackendClosed`, waits out a `Random` in flight and leaves no device, session or shared memory open. ([#347](https://github.com/jeremyhahn/go-enclave/issues/347))
- **arm-trustzone**: Tests cover `Backend.Random` over the fake TEE on both driver kinds, chunk by chunk, so a TA error, an INVOKE ioctl error or a cancel on any chunk returns no handle and leaves no shared memory live. ([#347](https://github.com/jeremyhahn/go-enclave/issues/347))
- **arm-trustzone**: Every exported error type and sentinel of `backends/armtrustzone` is held to one contract table test (messages, `errors.Is`, `errors.As` through `%w` and `errors.Join`, `Unwrap`), with a completeness check that fails on any exported error without a row. ([#375](https://github.com/jeremyhahn/go-enclave/issues/375))

### Fixed

- **arm-trustzone**: A trusted-application UUID with a dash in a hex-digit position is now refused with `*UUIDError` instead of being read with that dash skipped. ([#458](https://github.com/jeremyhahn/go-enclave/issues/458))

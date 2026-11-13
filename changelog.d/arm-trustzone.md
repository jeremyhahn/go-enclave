### Added

- **arm-trustzone**: every exported error type and sentinel of `backends/armtrustzone` is held to one contract table test (messages, `errors.Is`, `errors.As` through `%w` and `errors.Join`, `Unwrap`), with a completeness check that fails on any exported error without a row.

### Added

- `backends/armtrustzone` holds every exported error type and sentinel to one contract in a table test: the message on zero and populated values, `errors.Is` against every package sentinel, `errors.As` through `%w` and `errors.Join`, and `Unwrap`. A completeness check parses the package source and fails on any exported `...Error` type or `Err...` sentinel without a row.

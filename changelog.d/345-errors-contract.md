### Added

- One contract test for every exported error type of the root package: `Error()` on zero and populated values carries the `enclave: ` prefix and never panics, `errors.Is` matches the type's own sentinels and no other, `errors.As` and `Unwrap` work through `%w` and `errors.Join`, and raw bytes in a caller-supplied name never reach a message verbatim; a completeness check fails on any exported error type or `Err...` sentinel added without a row (#345).

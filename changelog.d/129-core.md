### Changed — BREAKING: the deprecated `MemoryEnclave` accessors are removed

- **`MemoryEnclave.Open`, `MemoryEnclave.OpenString` and
  `NewMemoryEnclaveFromString` are removed** (#129). Read through `WithBytes`,
  and bring string material in as `NewMemoryEnclave([]byte(s))`. `Open`'s slice
  outlived the lock, so a concurrent `Destroy` or `WipeAll` unmapped it under
  its reader; every read is now a borrow.
- The enclave and allocator core is restructured with no other behavior change
  (#129): every constructor ends in one publish step, `Allocator.New` and
  `NewSized` share one admission step and refund, and `Destroy` and `WipeAll`
  book every release, orphans included, through one step. `admission.go` and
  `process_allocator.go` become `allocator.go`, `Wipe` and the constant-time
  helpers move to `constanttime.go`, and the process allocator lives in a
  generic install-once slot (`singleton.go`).

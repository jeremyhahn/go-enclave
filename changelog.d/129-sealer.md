### Changed — sealing code split by concern

- **The sealing implementation is split into cohesive files** (#129):
  `sealer.go` keeps the `Sealer` type and its direct API; the `ModeRootKey`
  hierarchy moves to `hierarchy.go`, blob framing and the one key wrap shared
  by the hierarchy and `SoftwareProvider` to `keywrap.go`, and the AEAD
  primitives to `aead.go`; `sealed.go` keeps only `SealedEnclave`. Tests
  follow the same file names. No exported identifier, error or behaviour
  changes.
- Each hierarchy state check, key wrap, key-set destroy and
  destroy-on-failure step now has one implementation, and the provider error
  shaping is one table-driven `providerFailure` (#129).

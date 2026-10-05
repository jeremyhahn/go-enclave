### Changed

- **BREAKING: `WithKeyProtector(KeyProtector)` and `WithRootUnsealer(RootUnsealer)`
  replace `WithProvider(any)` and `WithMode`** (#108). The option selects the
  mode, so a provider that cannot serve it no longer compiles; `ErrProviderMode`
  and `ErrInvalidMode` are removed. A nil or typed-nil provider, or both
  options at once, returns the new `ErrInvalidProvider`.
- **BREAKING: `WithProviderHealth` is replaced by the `HealthReporter`
  interface** (#108). A `KeyProtector` that implements `Health() error` is
  found by type assertion and believed by `SealedEnclave.Openable`;
  `SoftwareProvider` implements it.
- **BREAKING: `(*SealedEnclave).Destroy` returns `error`** (#108), matching
  `MemoryEnclave.Destroy` and `Sealer.Destroy`. It is always `nil` today.

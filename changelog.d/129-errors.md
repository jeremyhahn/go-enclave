### Changed — BREAKING: one typed-error layer; `errors.Join` composites become typed errors

- **Seal and open failures are `*SealError` and `*OpenError`** (#129), not
  `errors.Join` composites. They match `ErrSealFailed` / `ErrOpenFailed` and
  unwrap to the cause, so every `errors.Is` match on the sentinels,
  `ctx.Err()`, `context.Cause` and the provider's error still holds. A sweep
  that meets a failure reports the new `*SealerWipedError`, matching
  `ErrSealerWiped`. Code that walked `Unwrap() []error` must use
  `errors.Is`/`errors.As`. A failure together with an independent cleanup
  failure is still joined, so it matches both.
- **`LockedMemoryError.Cause` is an `error`** (#129), was `any`.
- **`ProcessHardeningError` matches the new `ErrProcessHardeningFailed`**
  (#129).
- **Cause-carrying error types share one shape** (#129):
  `LockedMemoryError`, `UnwipedReleaseError`, `LimitDiscoveryError`,
  `ProcessHardeningError` and the new sealing types are aliases of one
  generic type with a `Cause error` field, rendering as the sentinel's text,
  `": "` and the cause. Struct literals and `errors.As` targets are unchanged.
- **`BudgetError` and `BudgetInUseError` messages read `<N> bytes
  requested`** (#129), was `<N> requested`.
- **`providertest.AbortedError` renders as `ErrAborted`'s text followed by the
  context's error** (#129); its `Err` field and matches are unchanged.
- Every root sentinel and error type is declared in `errors.go`, and every
  `providertest` one in `providertest/errors.go` (#129).

### Changed — BREAKING:

- **Every call that can reach a provider takes a `context.Context`** (#87).
  A provider can block for as long as its device does, and a deadline is
  only real if every layer between the caller and the blocking call honors
  it. The provider seam is now
  `KeyProtector.Protect(ctx, key)`, `KeyProtector.Unprotect(ctx, blob, key)`
  and `RootUnsealer.UnsealRoot(ctx, dst)`. The calls that reach it take the
  context first: `NewSealed(ctx, data)`, `(*Sealer).Seal(ctx, data)`,
  `(*SealedEnclave).Open(ctx)` and `(*SealedEnclave).OpenWith(ctx, a)`.
  The context is checked before every provider call and again after it
  returns. A context that has ended fails a seal with an error matching both
  `ErrSealFailed` and `context.Canceled` / `context.DeadlineExceeded`, and an
  open with one matching both the new `ErrOpenFailed` and the context's error.
  Neither matches `ErrSealedAuthentication`, with one deliberate exception:
  if the provider itself reports an authentication failure and the context
  has ended by the time it returns, the error carries both, because that
  verdict is a security signal and must not be overwritten. A refused seal
  still wipes the caller's data, and a `NewSealed` refused for its context
  installs no process sealer, so a later `SetSealer` still succeeds. When
  the context ends during a successful root unseal and the KEK mint then
  fails, the error carries both the cancellation and the mint failure, and
  the root is kept. A refused open costs no locked memory and no `Allocator`
  reservation, and the value stays intact.
  `SoftwareProvider` refuses an ended context before touching, or
  generating, its root. Provider authors: see the context contract on
  `RootUnsealer`.
- **A `ModePerOperation` provider's infrastructure failure on open is now
  joined under `ErrOpenFailed`** (#87), where it used to surface bare. The
  provider's own error is still reachable through `errors.Is` and `errors.As`.
  Authentication refusals, `ErrSealerWiped` and `ErrLockedMemoryUnavailable`
  still pass through untouched while the caller's context is live. If the
  provider returns one of them as the context ends, the error is the
  cancellation (`ErrOpenFailed` or `ErrSealFailed`, plus the context's
  error) joined with the provider's error, and matches all of them.
- **`(*SealedEnclave).Destroy` no longer waits for an `Open` in flight** (#87).
  `Destroy` takes no context, and an open can sit in a provider call
  indefinitely. An open already in flight completes against the envelope it
  pinned, opens that start after `Destroy` return `ErrEnclaveDestroyed`, and
  the last open out wipes the ciphertext.
- **`providertest.TestProvider(ctx, cfg)`** takes a context and passes it to
  every provider call (#87). A run whose context ends early returns an error
  matching the new `providertest.ErrAborted` (an `*AbortedError`), never `nil`.
  A provider call refused only because the run's own context ended is not
  charged to the provider, and neither is a call the run stopped waiting for:
  an unfinished call shows only that the run ended, not that the provider
  misbehaved. Violations observed before the abort are still reported.

### Added

- **The conformance suite checks the provider's half of the context
  contract** (#87). Protect, Unprotect and UnsealRoot are each called with an
  already-canceled context and with an already-expired one. Each call must
  fail with an error matching that context's error, and never as
  `ErrSealedAuthentication`. It must write no key material into the
  destination and must leave the provider able to serve the next call.
  For `UnsealRoot` that last property means a one-shot handle survives a
  refused call, because a `Sealer` retries a failed unseal. Such calls run on
  their own goroutine, so a provider that never returns cannot hold a run
  whose context is bounded; the run is reported aborted. Cancellation that arrives mid-call can only be forced from inside a
  provider, so the suite does not measure it.

### Fixed

- **No mutex of a `Sealer`'s is held across a provider call** (#87). The
  first-time `ModeRootKey` initialization held the sealer's mutex across
  `UnsealRoot`. A provider stalled there stalled every `Seal`, `Open` and
  `Openable` on that sealer, and none of them could give up. The unseal now
  runs under a one-slot init semaphore whose acquisition selects on the
  caller's context. The mutex is taken only to read the published hierarchy
  and to publish it. The semaphore is the one lock that does span the
  unseal, and a caller queued on it leaves when its own context ends.
  At-most-once `UnsealRoot` (#83), the wiped-state
  fail-closed contract and KEK rotation are unchanged. `SealedEnclave` no
  longer holds its own lock across an open either.
- **A shutdown sweep that overlaps the first root unseal leaves the sealer
  wiped** (#87). A sweep cannot reclaim the root while the provider is
  still writing into it. A sweep whose context ends while it waits on that
  borrow leaves the root behind, and the root used to be published
  afterwards. A refused release of a discarded root is reported alongside
  `ErrSealerWiped`, and the root stays on the `WipeAll` ledger until a later
  attempt or sweep reclaims it. The sweep sequence is now read before the unseal and
  compared on every exit after it: before the KEK mint, after a failed mint,
  and at publication. If a sweep overlapped, the root (and the KEK, if one was
  minted) is destroyed and the sealer reports `ErrSealerWiped` without asking
  the provider again. A mint that keeps failing can no longer keep a swept
  root resident behind an allocation error.

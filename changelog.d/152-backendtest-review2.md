### Added

- **`backendtest.Config.VerifyEvidence`** (#152): the attestation's relying party. With it, evidence for a nonce must verify against that nonce and not against another; without it every `Attester` is reported as an `*UncheckedCapabilityError`, never certified.

### Fixed

- **`backendtest` certified attestation from evidence that merely differed between calls** (#152), so a backend returning fresh random evidence that binds no nonce passed. Binding is now judged by `Config.VerifyEvidence`.
- **`backendtest` stopped probing a frozen view at its first fault** (#152), so a `Freeze` that protected only the first page passed. Every page and the view's first and last byte are now probed, each in its own call.
- **`backendtest` failed a `Destroy` that returned the retryable `ErrLockedMemoryUnavailable`** (#152). Such a `Destroy` is now called again, up to four calls in all; only a nil return obliges the handle to be dead, and any other error stays a failure. The concurrent-use check follows the same rule.
- **`backendtest`'s concurrent-use check could miss a `Destroy` race** (#152): it left out `Size`, `IsAlive`, `Backend` and `Freeze`, waited a fixed sleep for operations to start, and stopped each goroutine at its first `ErrEnclaveDestroyed`. The goroutines now start from a barrier, every one of those operations runs during the race and again after `Destroy` returns, and `Destroy` is called only once an operation is under way, with a `WithBytes` borrow held open across it.

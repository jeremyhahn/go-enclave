### Added

- **`providertest` catches forgeable and racy providers** (#146).
  `Config.PublicKey` declares a provider whose `Protect` needs no secret, and
  `Config.Forge` builds the blob an attacker holding its public key could;
  `Unprotect` must refuse it with `ErrSealedAuthentication`, which a bare
  RSA-OAEP or ECIES wrap does not. `PublicKey` without `Forge` returns
  `ErrNotMeasured` unless `Config.SkipForgery` records why. A new check runs
  round trips from 8 goroutines at once on one provider and requires each to
  recover its own key, so shared unsynchronized state fails without `-race`.
  The two destination spies now also require the later `Unprotect` to recover
  its own key.

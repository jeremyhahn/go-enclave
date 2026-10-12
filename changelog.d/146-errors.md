### Added

- **`providertest.FindingsError`** (#146). `TestProvider` returns one
  `*FindingsError` whose `Findings` are every `*PropertyError`,
  `*NotMeasuredError` and `*AbortedError` of the run, in order; `errors.Is` and
  `errors.As` reach each one.

### Changed — BREAKING:

- **`providertest.AbortedError.Err` is renamed `Cause`** (#146), like every
  other cause-carrying error type. See
  [Upgrading](docs/README.md#v090-from-v08).
- **No failure is an `errors.Join` composite** (#146). A failure that came with
  a failed cleanup, or several refused releases, such as from
  `(*Sealer).Destroy`, `(*SoftwareProvider).Destroy` or a rolled-back
  construction, is one `*CleanupError` (`ErrCleanupFailed`) carrying the
  operation's `Failure` and every refusal in `Causes`. Every sentinel and cause
  it carries still matches.

### Changed

- **The error types are defined types, not aliases of a generic one** (#146),
  so `go doc` shows each type's fields and its `Error`, `Is` and `Unwrap`
  methods. Struct literals, `errors.Is` and `errors.As` are unchanged.

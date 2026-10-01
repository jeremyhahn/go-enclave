### Added

- **`providertest` errors are typed: `ErrInvalidConfig`, `ConfigError` and
  `PropertyError`** (#83). A harness mistake and a provider defect used to be
  distinguishable only by parsing the message. A `Config` that cannot be run
  now returns a `*ConfigError` naming the field, matching `ErrInvalidConfig`
  under `errors.Is`; a provider that ran and failed returns one
  `*PropertyError` per failed property, joined, so each can be walked and
  inspected. The messages are unchanged, and the package no longer uses
  `fmt.Errorf`.

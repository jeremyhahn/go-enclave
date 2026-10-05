# Provider conformance — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-04
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; the suite runs inside the provider
author's test binary. Other transports are not applicable (see
[locked-memory/api.md](../locked-memory/api.md#transports)).

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Run the conformance suite | `providertest.TestProvider(ctx, providertest.Config{...})` | N/A |
| Distinguish harness error / aborted run / provider defect | `errors.Is(err, providertest.ErrInvalidConfig)`, `errors.Is(err, providertest.ErrAborted)`, `errors.Is(err, providertest.ErrNotMeasured)`, `var pe *providertest.PropertyError; errors.As(err, &pe)` | N/A |

Schemas and error mapping: [engineering.md](engineering.md).

## Versioning

v0.7 is BREAKING: `TestProvider(cfg)` became `TestProvider(ctx, cfg)`, and
`ErrAborted`/`AbortedError` are new. The suite also gained the ended-context
checks, so a provider that passed under v0.6 but ignores its context now fails.
See [user.md](user.md#migrating-from-v06).

`ErrNotMeasured`/`NotMeasuredError` are new and BREAKING in behavior: a
residue sweep that cannot run (non-Linux, no locked memory, blind control) used
to be logged and return `nil`; it now returns an error matching
`ErrNotMeasured` unless `Config.SkipResidueSweep` is set. Every error message
now starts with `providertest:`.

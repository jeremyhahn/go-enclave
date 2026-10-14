# Provider conformance — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-14
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

## Exported symbols

Package `providertest`: `TestProvider`, `Config` (fields `New`, `Modes`,
`SkipResidueSweep`, `SingleUseRoot`, `PublicKey`, `Forge`, `SkipForgery`,
`Logf`); sentinels `ErrInvalidConfig`, `ErrAborted`, `ErrNotMeasured`; error
types `ConfigError`, `AbortedError`, `NotMeasuredError`, `PropertyError`,
`FindingsError`. Contracts and error mapping:
[engineering.md](engineering.md#exported-surface).

The reference provider is the `enclave.SoftwareProvider` interface that
`enclave.NewSoftwareProvider()` returns, which `providertest`'s own tests hold
to the suite; its contract is in
[sealing/engineering.md](../sealing/engineering.md#exported-surface).

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

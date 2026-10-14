# Backend conformance — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-14
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; the suite runs inside the backend
author's test binary. Other transports are not applicable (see
[locked-memory/api.md](../locked-memory/api.md#transports)).

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Run the conformance suite | `backendtest.TestBackend(ctx, backendtest.Config{...}) error` | N/A |
| Describe the backend | `backendtest.Config{New, BackendCapabilities, Handles, SkipResidueSweep, VerifyEvidence, Logf}` | N/A |
| Describe a kind of handle | `backendtest.HandleCase{Name, New, Import, ImportSize, Capabilities}` | N/A |
| Tell a harness error from a run that did not finish, from a backend defect | `errors.Is(err, backendtest.ErrInvalidConfig)`, `errors.Is(err, backendtest.ErrAborted)`, `var fe *backendtest.FindingsError; errors.As(err, &fe)` | N/A |
| Tell what a finding is | `errors.Is(err, backendtest.ErrNotMeasured)`, `errors.Is(err, backendtest.ErrUncheckedCapability)`, `var pe *backendtest.PropertyError; errors.As(err, &pe)` | N/A |

## Exported symbols

`TestBackend`, `Config`, `HandleCase`; sentinels `ErrInvalidConfig`,
`ErrAborted`, `ErrNotMeasured`, `ErrUncheckedCapability`; error types
`ConfigError`, `AbortedError`, `NotMeasuredError`, `UncheckedCapabilityError`,
`FindingsError` and `PropertyError`, which has no sentinel (match it with
`errors.As`). Contracts and error mapping:
[engineering.md](engineering.md#exported-surface).

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

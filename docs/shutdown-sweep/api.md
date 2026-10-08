# Shutdown sweep — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-07
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; other transports are not
applicable (see [locked-memory/api.md](../locked-memory/api.md#transports)).
A remote "wipe everything" verb would be a remotely triggerable destroyer of
every key in the process; it is deliberately absent.

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Reclaim all locked memory at shutdown | `enclave.WipeAll(ctx) (int, error)` | N/A |
| Inspect findings | `var se *enclave.SweepError; errors.As(err, &se)` → `se.Corrupt`, `se.Unwiped` | N/A |
| Detect a non-admitted call | `errors.Is(err, enclave.ErrSweepInProgress)` | N/A |

Schemas and error mapping: [engineering.md](engineering.md#return-values).

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

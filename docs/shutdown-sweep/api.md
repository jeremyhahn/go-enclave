# Shutdown sweep — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-11
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; other transports are not
applicable (see [locked-memory/api.md](../locked-memory/api.md#transports)).
A remote "wipe everything" verb would be a remotely triggerable destroyer of
every key in the process; it is deliberately absent.

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Reclaim all locked memory at shutdown | `enclave.WipeAll(ctx) (int, error)` | N/A |
| Inspect findings | `var se *enclave.SweepError; errors.As(err, &se)` → `se.Corrupt`, `se.Unwiped`, `se.Backends` | N/A |
| Detect a non-admitted call | `errors.Is(err, enclave.ErrSweepInProgress)` | N/A |

Schemas and error mapping: [engineering.md](engineering.md#error-semantics).

## Types

| Symbol | Shape | Notes |
|---|---|---|
| `SweepError` | `{Corrupt int; Unwiped int; Backends []BackendSweepFailure}` | Returned by `WipeAll` as `*SweepError` when an admitted sweep found something. `Unwrap() []error` returns each failed backend's error. |
| `BackendSweepFailure` | `{Backend string; Err error}` | A record, not an error type: one `Sweeper` whose `Sweep` failed. `Backend` is its registered name, `Err` what it returned, unchanged. Reached only through `SweepError.Backends`, in name order. |

## Errors

| Sentinel | Typed error | Meaning |
|---|---|---|
| `ErrSweepInProgress` | none | The call was not admitted and swept nothing. |
| `ErrEnclaveCorrupted` | via `*SweepError` (`Corrupt > 0`) | Declared in [locked-memory](../locked-memory/api.md). |
| `ErrReleasedWithoutWipe` | via `*SweepError` (`Unwiped > 0`) | Declared in [locked-memory](../locked-memory/api.md). |

A failed backend's own error is matched through `SweepError`'s `Unwrap`.

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

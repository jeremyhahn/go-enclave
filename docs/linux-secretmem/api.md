# Linux secretmem backend — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-27
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; other transports are not
applicable (see [memory-enclave/api.md](../memory-enclave/api.md#transports)).

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Build the backend over an `Allocator` | `enclave.NewSecretMemory(a)` | N/A |
| Probe whether this host allows `memfd_secret` | `Prober.Probe(ctx)` on the backend, or `enclave.Detect(ctx)` once it is registered | N/A |
| Import material into secretmem memory | `Importer.Import(ctx, material, opts...)` on the backend | N/A |
| Open a sealed value into secretmem memory | `Sealed.OpenIn(ctx, backend)`: decrypts straight into a handle's secretmem pages | N/A |

Schemas and error mapping: [engineering.md](engineering.md). No permission
scope; no pagination.

## Exported symbols

Every exported symbol of the feature. The contract of each is in
[engineering.md](engineering.md#exported-surface); this table names it.

| Symbol | Kind | Notes |
|---|---|---|
| `NewSecretMemory` | function | `NewSecretMemory(a Allocator) (Backend, error)`. The `Backend` is an `Importer` and a `Prober` of rank 1. |
| `SecretMemoryBackendName` | string constant | `"linux-secretmem"`: the backend's `Name`. |

Its handles are memory enclaves: `Handle`, `ByteAccess` and `Freezer`
([backends](../backends/api.md)).

### Errors

Sentinel: `ErrMemfdSecretUnavailable`. Type: `*MemfdSecretError` (`Cause`),
matching `ErrMemfdSecretUnavailable` and unwrapping to `Cause`. The budget
refusal is the existing `*BudgetError` ([locked-memory budget](../locked-memory-budget/api.md)).
Match a sentinel with `errors.Is` and read a type with `errors.As`; meaning
and handling: [engineering.md](engineering.md#error-semantics).

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

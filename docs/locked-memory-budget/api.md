# Locked-memory budget and admission — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-11
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; other transports are not
applicable (see [locked-memory/api.md](../locked-memory/api.md#transports) for
why a bottom-layer library has none).

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Create a budget | `enclave.NewAllocator(maxBytes)` | N/A |
| Create a budget checked against `RLIMIT_MEMLOCK` | `enclave.NewAllocatorWithinRLimit(maxBytes)` | N/A |
| Admitted allocation (move / generate) | `(*Allocator).New(data)`, `(*Allocator).NewSized(n)` | N/A |
| Admitted open of a sealed value | `(*Sealed).OpenIn(ctx, a)` ([sealing](../sealing/api.md)) | N/A |
| Admitted import as the locked-memory backend | `(*Allocator).Name()`, `(*Allocator).Import(ctx, material, opts...)` ([backends](../backends/api.md)) | N/A |
| Retune | `(*Allocator).SetLimit(n)`, `(*Allocator).ForceLimit(n)` | N/A |
| Rebalance | `(*Allocator).TransferTo(dst, n)` | N/A |
| Observe | `(*Allocator).InUse()`, `Limit()`, `Available()` | N/A |
| Install / use the process budget | `enclave.SetAllocator(a)`, `enclave.ProcessAllocator()` | N/A |
| Read the ceiling | `enclave.DiscoverLockedMemoryLimit()` | N/A |
| Cost of one enclave | `enclave.LockedSize(n)` | N/A |

Schemas and error mapping: [engineering.md](engineering.md). No permission
scope; no pagination.

## Types

| Symbol | Shape | Notes |
|---|---|---|
| `Allocator` | handle on one shared budget | Built only by `NewAllocator` / `NewAllocatorWithinRLimit`; a copy is the same allocator, a zero `Allocator{}` refuses every call. |
| `LockedMemoryLimit` | `{Bytes int64; Bounded bool; Source LimitSource}` | Snapshot from `DiscoverLockedMemoryLimit`. `Bytes` is a ceiling only when `Bounded`; it is populated for `LimitNotEnforced` and zero when nothing was read. |
| `LimitSource` | `uint8`, with `String()` | Where a `LockedMemoryLimit` came from; the constants below. |

### `LimitSource` values

| Constant | Meaning | `Bounded` |
|---|---|---|
| `LimitUnknown` | The zero value; appears only in the zero `LockedMemoryLimit` returned with an error. | no |
| `LimitRLimit` | A finite `RLIMIT_MEMLOCK` soft limit binds the process. | yes |
| `LimitUnlimited` | `RLIM_INFINITY`, or a value beyond any `int64` budget. | no |
| `LimitNotEnforced` | A finite limit was read, but the calling thread holds `CAP_IPC_LOCK` in the initial user namespace (Linux). | no |
| `LimitUnsupported` | The platform has no per-process locked-memory limit (Windows, AIX, Solaris, illumos); nothing was read. | no |

Per-platform discovery: [engineering.md](engineering.md#platform-contract-for-discovery).

## Errors

Every sentinel is declared in [errors.go](../../errors.go). Match with
`errors.Is` / `errors.As`; the error types carry diagnostic fields only.
When each is returned: [engineering.md](engineering.md#error-semantics).

| Sentinel | Typed error | Fields |
|---|---|---|
| `ErrBudgetExhausted` | `*BudgetError` | `Requested` (page-rounded charge), `InUse`, `Limit`, all `int64`. |
| `ErrInvalidBudget` | none | n/a |
| `ErrBudgetInUse` | `*BudgetInUseError` | `Requested` (the budget asked for; for `TransferTo`, what the source would be left with), `InUse`, `Limit` (the unchanged budget). |
| `ErrInvalidTransfer` | none | n/a |
| `ErrNilAllocator` | none | n/a |
| `ErrAllocatorNotConstructed` | none | n/a |
| `ErrAllocatorInstalled` | none | n/a |
| `ErrBudgetExceedsRLimit` | `*RLimitError` | `Requested int64`, `Limit LockedMemoryLimit` (always `Bounded`). |
| `ErrLimitDiscoveryFailed` | `*LimitDiscoveryError` | `Cause error`; `Unwrap` returns the `getrlimit` failure. |

`ErrLockedMemoryUnavailable` also reaches this feature (admitted, then refused by
the kernel); it belongs to [locked-memory](../locked-memory/api.md).

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

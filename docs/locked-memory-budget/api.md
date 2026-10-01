# Locked-memory budget and admission — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-01
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
| Admitted open of a sealed value | `(*SealedEnclave).OpenWith(ctx, a)` ([sealing](../sealing/api.md)) | N/A |
| Retune | `(*Allocator).SetLimit(n)`, `(*Allocator).ForceLimit(n)` | N/A |
| Rebalance | `(*Allocator).TransferTo(dst, n)` | N/A |
| Observe | `(*Allocator).InUse()`, `Limit()`, `Available()` | N/A |
| Install / use the process budget | `enclave.SetAllocator(a)`, `enclave.ProcessAllocator()` | N/A |
| Read the ceiling | `enclave.DiscoverLockedMemoryLimit()` | N/A |
| Cost of one enclave | `enclave.LockedSize(n)` | N/A |

Schemas and error mapping: [engineering.md](engineering.md). No permission
scope; no pagination.

## Versioning

No breaking change to this capability in v0.7. Code that pairs
`SetAllocator` with a shutdown sweep must move to `WipeAll(ctx)`
([shutdown-sweep](../shutdown-sweep/user.md#migrating-from-v06)), and
`OpenWith` now takes a context ([sealing](../sealing/user.md#migrating-from-v06)).

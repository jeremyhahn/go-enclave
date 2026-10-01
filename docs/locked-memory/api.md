# Locked-memory enclaves — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-01
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

go-enclave is a bottom-layer library with no server process. The **embedded Go
call is its only transport**. REST, gRPC, QUIC, MCP and Unix-socket forms are
*not applicable*, not missing: the capability is "hold bytes in this process's
locked memory", and exporting it over a transport would move the material out of
the memory it protects. Higher layers that expose key operations over a
transport own those surfaces.

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Bring existing material into locked memory (move) | `enclave.NewMemoryEnclave(data)` | N/A |
| Bring existing material in (copy, source kept) | `enclave.NewMemoryEnclaveCopy(src)` | N/A |
| Bring a string in | `enclave.NewMemoryEnclaveFromString(s)` | N/A |
| Generate in place | `enclave.NewMemoryEnclaveSized(n)` then `WithBytes`, `Freeze` | N/A |
| Read under lock | `(*MemoryEnclave).WithBytes(fn)`, `OpenString()`, `EqualTo(b)`, `EqualToErr(b)` | N/A |
| Unlocked view (unsafe) | `(*MemoryEnclave).Open()` | N/A |
| Make read-only | `(*MemoryEnclave).Freeze()` | N/A |
| Inspect | `(*MemoryEnclave).Size()`, `(*MemoryEnclave).IsAlive()`, `(*MemoryEnclave).String()` | N/A |
| Release | `(*MemoryEnclave).Destroy() error` | N/A |
| Cost of an enclave | `enclave.LockedSize(n) int64` | N/A |
| Core-dump hardening status | `enclave.CoreDumpsDisabled() error` | N/A |
| Zero a heap slice | `enclave.Wipe(b)` | N/A |

Request and response schemas are the Go signatures in
[engineering.md](engineering.md#exported-surface); error mapping is in
[engineering.md](engineering.md#error-semantics). There is no authentication or
permission scope: anything in the process that holds the `*MemoryEnclave` can
use it. No result set is unbounded, so there is no pagination.

## Versioning

Pre-1.0 (`v0.y.z-alpha`): breaking changes land in a MINOR bump with a
`BREAKING` changelog heading. The v0.7 changes to this capability are
`Destroy() error` (replacing `Destroy()` + `DestroyErr()`) and the Windows
result of `CoreDumpsDisabled`; see [user.md](user.md#migrating-from-v06).

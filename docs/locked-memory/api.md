# Locked-memory enclaves — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-07
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
| Generate in place | `enclave.NewMemoryEnclaveSized(n)` then `WithBytes`, `Freeze` | N/A |
| Read under lock | `(*MemoryEnclave).WithBytes(fn)`, `EqualTo(b) (bool, error)` | N/A |
| Make read-only | `(*MemoryEnclave).Freeze()` | N/A |
| Inspect | `(*MemoryEnclave).Size()`, `(*MemoryEnclave).IsAlive()`, `(*MemoryEnclave).String()` | N/A |
| Release | `(*MemoryEnclave).Destroy() error` | N/A |
| Cost of an enclave | `enclave.LockedSize(n) int64` | N/A |
| Core-dump hardening status | `enclave.CoreDumpsDisabled() error` | N/A |
| Opt-in process hardening | `enclave.HardenProcess() (ProcessHardening, error)` | N/A |
| Zero a heap slice | `enclave.Wipe(b)` | N/A |

Request and response schemas are the Go signatures in
[engineering.md](engineering.md#exported-surface); error mapping is in
[engineering.md](engineering.md#error-semantics). There is no authentication or
permission scope: anything in the process that holds the `*MemoryEnclave` can
use it. No result set is unbounded, so there is no pagination.

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

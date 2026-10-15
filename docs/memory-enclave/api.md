# Locked-memory enclaves — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-14
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
| Bring existing material into locked memory (move) | `enclave.NewMemory(data) (ByteAccess, error)` | N/A |
| Bring existing material in (copy, source kept) | `enclave.NewMemoryCopy(src) (ByteAccess, error)` | N/A |
| Generate in place | `enclave.NewMemorySized(n) (ByteAccess, error)` then `WithBytes`, and `Freeze` through `Freezer` | N/A |
| Read under lock | `ByteAccess.WithBytes(fn)`, `EqualTo(b) (bool, error)` | N/A |
| Make read-only | `Freezer.Freeze()`: `enclave.As(e, &f)` or `e.(enclave.Freezer)` | N/A |
| Inspect | `Handle.Size()`, `Handle.IsAlive()`; `%v` and `%s` print it redacted | N/A |
| Mask under `%#v` | prints the same redacted text | N/A |
| Release | `Handle.Destroy() error` | N/A |
| Which backend holds it | `Handle.Backend() Backend` | N/A |
| Cost of an enclave | `enclave.LockedSize(n) int64` | N/A |
| Core-dump limit status (after `HardenProcess`) | `enclave.CoreDumpsDisabled() error` | N/A |
| Opt-in process hardening | `enclave.HardenProcess() (ProcessHardening, error)` | N/A |
| Zero a heap slice | `enclave.Wipe(b)` | N/A |

The constructors return the `ByteAccess` interface; the enclave behind it is a
`*Memory`, which is also a `Freezer`. Its `String()` returns `Memory(redacted)`
for a live enclave and `Memory(destroyed)` once it is destroyed, and its
`GoString()` returns the same text, so `%v`, `%s` and `%#v` never print the
contents. A failed constructor returns a nil interface.

## Process hardening

`HardenProcess` returns a `ProcessHardening` report (`NotDumpable`,
`CoreDumpsDisabled`); a field is true only when the protection was read back in
effect. `CoreDumpsDisabled() error` reports the `RLIMIT_CORE` step of the last
`HardenProcess`. Contracts: [engineering.md](engineering.md#exported-surface);
why hardening is opt-in: [architecture.md](architecture.md#process-hardening).

## Errors

Sentinels: `ErrEmptyEnclave`, `ErrEnclaveDestroyed`, `ErrInvalidSize`,
`ErrLockedMemoryUnavailable`, `ErrReleasedWithoutWipe`, `ErrCleanupFailed`,
`ErrEnclaveCorrupted`, `ErrNilFunc`, `ErrCoreDumpLimitUnsupported`,
`ErrCoreDumpLimitNotApplied`, `ErrCoreDumpLimitFailed`,
`ErrProcessHardeningUnsupported`, `ErrProcessHardeningFailed`. Cause-carrying
types: `*LockedMemoryError`, `*UnwipedReleaseError`, `*CleanupError`,
`*CoreDumpLimitError`, `*ProcessHardeningError`. Match a sentinel with
`errors.Is` and read a type with `errors.As`; when each is returned and what the
caller does about it: [engineering.md](engineering.md#error-semantics).

## Schemas and access

Request and response schemas are the Go signatures in
[engineering.md](engineering.md#exported-surface); error mapping is in
[engineering.md](engineering.md#error-semantics). There is no authentication or
permission scope: anything in the process that holds the enclave can
use it. No result set is unbounded, so there is no pagination.

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

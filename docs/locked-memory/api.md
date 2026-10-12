# Locked-memory enclaves — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-11
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
| Bring existing material into locked memory (move) | `enclave.NewMemory(data)` | N/A |
| Bring existing material in (copy, source kept) | `enclave.NewMemoryCopy(src)` | N/A |
| Generate in place | `enclave.NewMemorySized(n)` then `WithBytes`, `Freeze` | N/A |
| Read under lock | `(*Memory).WithBytes(fn)`, `EqualTo(b) (bool, error)` | N/A |
| Make read-only | `(*Memory).Freeze()` | N/A |
| Inspect | `(*Memory).Size()`, `(*Memory).IsAlive()`, `(*Memory).String()` | N/A |
| Mask under `%#v` | `(*Memory).GoString()` | N/A |
| Release | `(*Memory).Destroy() error` | N/A |
| Which backend holds it | `(*Memory).Backend() Backend` | N/A |
| Cost of an enclave | `enclave.LockedSize(n) int64` | N/A |
| Core-dump limit status (after `HardenProcess`) | `enclave.CoreDumpsDisabled() error` | N/A |
| Opt-in process hardening | `enclave.HardenProcess() (ProcessHardening, error)` | N/A |
| Zero a heap slice | `enclave.Wipe(b)` | N/A |

`(*Memory).String()` returns `Memory(redacted)` for a live enclave and
`Memory(destroyed)` once it is destroyed; `(*Memory).GoString()` returns the same
text, so `%v`, `%s` and `%#v` never print the contents.

## Process hardening

`HardenProcess` returns a `ProcessHardening` report. A field is true only when
the protection was read back in effect.

| Field | Meaning |
|---|---|
| `ProcessHardening.NotDumpable bool` | The process is marked non-dumpable (Linux `prctl(PR_SET_DUMPABLE, 0)`). |
| `ProcessHardening.CoreDumpsDisabled bool` | `RLIMIT_CORE` was lowered to zero, soft and hard. |

`CoreDumpsDisabled() error` reports the `RLIMIT_CORE` step of the last
`HardenProcess`: `nil` when it took, else one of the errors below. Why hardening
is opt-in, and its cost to the process, are in
[architecture.md](architecture.md#process-hardening) and
[engineering.md](engineering.md#configuration).

## Errors

Match a sentinel with `errors.Is` and read a type's `Cause` with `errors.As`.
When each is returned, and what the caller does about it, is in
[engineering.md](engineering.md#error-semantics).

| Sentinel | Error type | Returned when |
|---|---|---|
| `ErrEmptyEnclave` | none | An enclave is requested over zero bytes of material. |
| `ErrEnclaveDestroyed` | none | A destroyed enclave is borrowed, frozen or read. |
| `ErrInvalidSize` | none | `NewMemorySized` (or `Allocator.NewSized`) is given a size that is non-positive or too large to map. |
| `ErrLockedMemoryUnavailable` | `*LockedMemoryError{Cause}` | The kernel refused to map, lock, protect or release the pages (often the `RLIMIT_MEMLOCK` ceiling). Every `*LockedMemoryError` matches it. |
| `ErrReleasedWithoutWipe` | `*UnwipedReleaseError{Cause}` | `Destroy` unmapped the pages without the in-process wipe because `mprotect` was denied, or a constructor's rollback did. On `Destroy` it never also matches `ErrLockedMemoryUnavailable`; on a constructor's rollback it comes in a `*CleanupError` with the freeze failure, so that error matches both. |
| `ErrCleanupFailed` | `*CleanupError{Failure, Causes}` | A failure and an independent cleanup failure happened together (a refused rollback, a refused unlock). `Failure` is the operation's own error and `Causes` each refusal; it matches all of them and `ErrCleanupFailed`. Read it with `errors.As` and a `*CleanupError` target. |
| `ErrEnclaveCorrupted` | none | The canary or a guard page was overwritten, detected at release. |
| `ErrNilFunc` | none | `WithBytes` is given a nil function; the enclave is unchanged. |
| `ErrCoreDumpLimitUnsupported` | none | `CoreDumpsDisabled` on Windows, which has no process-wide core-dump limit. |
| `ErrCoreDumpLimitNotApplied` | none | `CoreDumpsDisabled` before `HardenProcess` has run. |
| `ErrCoreDumpLimitFailed` | `*CoreDumpLimitError{Cause}` | `HardenProcess` could not lower `RLIMIT_CORE` to zero, soft and hard. Every `*CoreDumpLimitError` matches it. |
| `ErrProcessHardeningUnsupported` | none | `HardenProcess` on a platform with neither step (Windows); nothing is applied. |
| `ErrProcessHardeningFailed` | `*ProcessHardeningError{Cause}` | A hardening step was refused or did not read back in effect. Every `*ProcessHardeningError` matches it; a failed `RLIMIT_CORE` step has a `*CoreDumpLimitError` as its `Cause`. |

## Schemas and access

Request and response schemas are the Go signatures in
[engineering.md](engineering.md#exported-surface); error mapping is in
[engineering.md](engineering.md#error-semantics). There is no authentication or
permission scope: anything in the process that holds the `*Memory` can
use it. No result set is unbounded, so there is no pagination.

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

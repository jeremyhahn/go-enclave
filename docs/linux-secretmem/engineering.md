# Linux secretmem backend — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-27
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

Design: [architecture.md](architecture.md). Code: `secretmem.go` (the
backend), `secretmem_linux.go` (the system calls),
`secretmem_unsupported.go` (the stub), and `mapBacked` in `mapping.go`.

## Exported surface

```go
const SecretMemoryBackendName = "linux-secretmem"

func NewSecretMemory(a Allocator) (Backend, error)

var ErrMemfdSecretUnavailable error

type MemfdSecretError struct {
	Cause error
}
```

| Symbol | Contract |
|---|---|
| `NewSecretMemory` | Returns the backend over `a`, or `ErrNilAllocator` / `ErrAllocatorNotConstructed` for a nil or zero `a`, or `ErrMemfdSecretUnavailable` on a build without the syscall. It makes no system call. The backend is an `Importer` and a `Prober`. |
| `Name` | `SecretMemoryBackendName`. |
| `Rank` | 1: above locked memory, below every hardware backend. |
| `Probe` | `ctx.Err()` when `ctx` is done (a nil `ctx` never ends), else the result of mapping, touching and releasing one secretmem page: nil, or a `*MemfdSecretError`. It leaves nothing behind, never panics, and is safe for concurrent use. |
| `Import` | Wipes `material` on every return path. It checks the `Allocator`, the options, the AES-256 key length, `ctx` and emptiness in that order before any system call, as the `Allocator`'s `Import` does. It then admits the length against the budget, maps it, loads the material and returns a frozen handle whose `Backend` is this backend. A failure refunds the budget and leaves no mapping. |
| `MemfdSecretError` | A refused `memfd_secret`, `ftruncate`, `mmap`, `close` or `munmap`, with `Cause` the `*os.SyscallError` naming the call. For a fault at first touch, `Cause` is the recovered `runtime.Error`. |

## Invariants

1. **Nothing registers or probes on import.** `main` builds and registers the
   backend, and `Detect` probes it.
2. **A handle is a memory enclave in secretmem.** The mapping layer reserves
   anonymous guard pages around the inner pages, `mapSecret` maps the
   secretmem file over the inner pages `MAP_SHARED|MAP_FIXED`, and the layer
   applies `MADV_DONTDUMP`, `MADV_DONTFORK`, the canary, the guards and the
   freeze. Wipe, freeze, release, canary checks and `WipeAll` are the memory
   enclave's.
3. **The material pages are never `mlock`'d.** The kernel maps them
   `VM_LOCKED`, and `mlock` on them fails `ENOMEM`. Release skips `munlock`;
   `munmap` drops the lock.
4. **The descriptor never outlives construction.** It is opened `O_CLOEXEC` and
   closed once mapped, on success and on every failure.
5. **Every page is touched before material is written**, under
   `debug.SetPanicOnFault`, so a `SIGBUS` at first fault is a typed error,
   never a crash.
6. **No silent fallback.** A refused `Import` returns its error; it never
   returns a memory enclave in secretmem's place.
7. **The stub's build tag is the exact complement of the implementation's**
   (`linux` on 386, amd64, arm64, loong64, riscv64 or s390x), so every target
   of `make cross-build` compiles exactly one.

## Error semantics

| Error | Means | Matches |
|---|---|---|
| `ErrMemfdSecretUnavailable`, bare | This build has no `memfd_secret`. | — |
| `*MemfdSecretError` | The host refused a call, or a page faulted at first touch. `Cause` names the call and errno: `ENOSYS` disabled or too old, `EPERM` filtered, `EAGAIN` no `RLIMIT_MEMLOCK` headroom, `ENOMEM`, `EMFILE` or `ENFILE` out of memory or descriptors. | `ErrMemfdSecretUnavailable`; it unwraps to `Cause`, so `errors.Is(err, unix.ENOSYS)` holds. Never `ErrLockedMemoryUnavailable`. |
| `*ProbeError` wrapping either | `Detect` passed the backend over. | `ErrBackendUnavailable` and the above. |
| `*BudgetError` | The `Allocator`'s budget refused the length. | `ErrBudgetExhausted`. |
| `ErrInvalidImport`, `ErrEmptyEnclave`, `ctx.Err()` | `Import`'s argument checks, before any system call. | — |

Texts are the sentinel's, then the cause's text. Match with `errors.Is` and
`errors.As`, never the text.

## Cost

The probe costs one locked page and one split of the kernel's direct map per
`Detect`. Each handle costs one `memfd_secret`, `ftruncate`, `mmap` and `close`
on top of the memory enclave's mapping calls, and one page split per material
page. The splits fragment the direct map's huge pages for the whole kernel, so
prefer a few long-lived handles to many short-lived ones.

## Configuration and persistence

None beyond the `Allocator` passed in. The backend keeps no state but the
`Allocator`; each handle's pages are released on `Destroy`.

## Test strategy

`secretmem_linux_test.go` runs on any Linux kernel. It injects refusals through
the `memfdSecret` seam: `ENOSYS`, `EPERM`, `ENOMEM` and `EMFILE` at the probe
and at `Import`, with the budget refunded. A `memfd_create` file stands in for a
secretmem one, so the success paths and the `ftruncate` and `mmap` refusals
(by `F_SEAL_GROW` and `F_SEAL_WRITE`) run where the kernel refuses secretmem.
It also covers the name and rank, construction without a system call, the
probe's `ctx` check, `Detect` keeping locked memory on each refusal and ranking
the backend between locked memory and a rank-2 backend, `Import`'s argument
checks, a budget refusal, the handle lifecycle, `WipeAll`, and a touch fault
caught as a typed error. One test uses the real syscall and skips, naming the
errno, where the host refuses it. It checks that `/proc/self/mem` cannot read
the material. `make test-linux-secretmem` runs these tests with the rest of
the root package.

`backendtest`'s `TestBackendConformance_SecretMemory` and the integration
suite's `TestLinuxSecretmem_PassesBackendConformance` run the
[conformance suite](../backend-conformance/engineering.md) against the
backend. The residue sweep is skipped, because it reads through
`/proc/self/mem`, which secretmem refuses. In an isolated child,
`TestLinuxSecretmem_DetectSelectsItAboveLockedMemory` registers the backend,
checks that `Detect` selects it, and checks that a handle reports it.
`make integration-test-linux-secretmem` runs the integration tests. Each skips
in the parent, naming the refusal, where the host refuses `memfd_secret`.

## Observability

`Detect`'s `ProbeResult` for `"linux-secretmem"` records whether the host
allows it and, if not, the errno. Every handle's `Backend().Name()` says its
material is in secretmem.

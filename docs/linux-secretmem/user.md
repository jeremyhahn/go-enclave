# Linux secretmem backend — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-27
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

`enclave.NewSecretMemory` is a software [backend](../backends/user.md) that
holds material in `memfd_secret(2)` memory. That memory is locked and kept out
of core dumps as the memory enclave's is. It is also removed from the kernel's
direct map, and `/proc/<pid>/mem`, `ptrace` and `process_vm_readv` cannot read
it. It ranks 1: [detection](../backend-detection/user.md) prefers it to locked
memory and every hardware backend to it ([architecture](architecture.md)).

## Prerequisites

- Linux 5.14 or later on 386, amd64, arm64, loong64, riscv64 or s390x, with
  `memfd_secret` enabled: on by default from 6.5, and before that only when the
  kernel boots with `secretmem.enable=1`.
- A seccomp profile or LSM that allows `memfd_secret`. Docker's default
  profile allows it.
- `RLIMIT_MEMLOCK` headroom for the material, as for locked memory
  ([locked-memory budget](../locked-memory-budget/user.md)).
- A host that does not hibernate: the kernel refuses to hibernate while any
  secretmem mapping exists. On a laptop or VM host that hibernates, do not
  register the backend.

Elsewhere the backend still builds: `NewSecretMemory` returns
`enclave.ErrMemfdSecretUnavailable`, and detection keeps the memory enclave.

## Register it and detect

Nothing registers the backend on import. `main` builds it over the
`Allocator` whose budget it shares with locked memory, registers it, and calls
`Detect`:

```go
alloc, err := enclave.NewAllocator(16 << 20)
if err != nil {
	return err
}
secretmem, err := enclave.NewSecretMemory(alloc)
switch {
case errors.Is(err, enclave.ErrMemfdSecretUnavailable):
	// Not a Linux build with memfd_secret: locked memory serves.
case err != nil:
	return err
default:
	if err := enclave.Register(secretmem); err != nil {
		return err
	}
}

backend, results := enclave.Detect(ctx)
```

Where the host refuses `memfd_secret`, `Detect` returns locked memory, and the
secretmem `ProbeResult.Err` says why. Construction makes no system call; only
the probe and `Import` do.

## Use its handles

A handle is a memory enclave with its material pages in secretmem: it is a
`ByteAccess` and a `Freezer`, it is returned frozen, and `Destroy` wipes and
releases it. `WipeAll` sweeps it. `handle.Backend().Name()` is
`enclave.SecretMemoryBackendName` (`"linux-secretmem"`).

```go
h, err := backend.(enclave.Importer).Import(ctx, material)
```

`Import` wipes `material` on every return path. A refusal is a
`*enclave.MemfdSecretError`, never a memory enclave in its place.

## Open sealed values into it

```go
h, err := sealed.OpenIn(ctx, backend)
```

`OpenIn` decrypts straight into a new handle's secretmem pages, admitted
against the backend's `Allocator` before anything is decrypted. The plaintext
never passes through a locked-memory scratch enclave or the heap, and
`Import` is not called. A refused `memfd_secret` is an `ErrOpenFailed`
carrying the `*enclave.MemfdSecretError`, a spent budget is a `*BudgetError`,
and the sealed value stays intact; nothing falls back to locked memory.

## Troubleshooting

| Error | Cause and fix |
|---|---|
| `ErrMemfdSecretUnavailable` with no cause, from `NewSecretMemory` | Not Linux, or a Linux architecture without the syscall. Locked memory serves. |
| `*MemfdSecretError`, cause `memfd_secret: function not implemented` | The kernel is older than 5.14, lacks `CONFIG_SECRETMEM`, or booted without `secretmem.enable=1` (before 6.5) or with `secretmem.enable=0`. |
| `*MemfdSecretError`, cause `memfd_secret: operation not permitted` | A seccomp profile or LSM filters the call. Allow `memfd_secret` in the profile. |
| `*MemfdSecretError`, cause `mmap: resource temporarily unavailable` | `RLIMIT_MEMLOCK` is exhausted. Raise it, or grant `CAP_IPC_LOCK`. |
| `*MemfdSecretError`, cause `cannot allocate memory`, or a recovered fault | The kernel could not allocate the page or split the direct map. |
| `*BudgetError` | The `Allocator`'s budget is spent, as for locked memory. |

Each `*MemfdSecretError` matches `enclave.ErrMemfdSecretUnavailable`; inside
`Detect`'s results it is wrapped in a `*ProbeError`.

## Upgrading

See [Upgrading](../README.md#upgrading).

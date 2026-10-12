# Locked-memory enclaves — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-11
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Exported surface

All in package `enclave` (import path `github.com/jeremyhahn/go-enclave`).

| Identifier | Contract |
|---|---|
| `NewMemory(data []byte) (*Memory, error)` | Moves `data` in and **wipes the caller's slice on every return path**. Result is frozen read-only. |
| `NewMemoryCopy(src []byte) (*Memory, error)` | Copies `src` in and leaves it **untouched on every path**. Result is frozen. The heap copy in `src` is the caller's to wipe. |
| `NewMemorySized(n int) (*Memory, error)` | `n` zeroed, **writable** bytes to fill through `WithBytes`; call `Freeze` when the fill is done. |
| `(*Memory).WithBytes(fn func([]byte) error) error` | The only access. Holds the read lock across `fn`; returns `fn`'s error. A nil `fn` is `ErrNilFunc`. |
| `(*Memory).EqualTo(other []byte) (bool, error)` | Compare under the read lock; a destroyed or nil enclave returns `ErrEnclaveDestroyed`. Time does not depend on the contents but does reveal whether the lengths differ. |
| `(*Memory).Size() int` / `IsAlive() bool` / `String() string` | Locked accessors; `String` never prints the material. |
| `(*Memory).Freeze() error` | `mprotect` the data read-only. Idempotent, irreversible, waits out borrows. |
| `(*Memory).Destroy() error` | Wipe, verify, unlock, unmap; idempotent, nil-safe. See below. |
| `(*Memory).Backend() Backend` | The `*Allocator` that admitted the enclave, else `DefaultBackend()` ([backends](../backends/engineering.md)). |
| `LockedSize(n int) int64` | Locked bytes an `n`-byte enclave costs (page-rounded); `0` for an impossible size. |
| `CoreDumpsDisabled() error` | What the last `HardenProcess` did to `RLIMIT_CORE`: `nil` when lowered to zero (soft and hard), else a `*CoreDumpLimitError`; `ErrCoreDumpLimitNotApplied` before one has run. |
| `HardenProcess() (ProcessHardening, error)` | Opt-in, never called by the package. Lowers `RLIMIT_CORE` to 0/0 where it exists (all but Windows) and, on Linux, sets `prctl(PR_SET_DUMPABLE, 0)`; each read back. Windows: `ErrProcessHardeningUnsupported`. |
| `ProcessHardening{NotDumpable, CoreDumpsDisabled bool}` | What `HardenProcess` verified in effect. |
| `ProcessHardeningError{Cause error}` | A refused or ineffective hardening step, the first that failed. Matches `ErrProcessHardeningFailed`; `Unwrap` reaches the `prctl` error or a `*CoreDumpLimitError`. |
| `CoreDumpLimitError{Cause error}` | A refused `setrlimit`, or a read-back that is not 0/0. Matches `ErrCoreDumpLimitFailed`. |
| `Wipe(b []byte)` | Best-effort zeroing of an ordinary heap slice. |
| `LockedMemoryError{Cause error}` | Matches `ErrLockedMemoryUnavailable`; `Unwrap` reaches the syscall error. |
| `UnwipedReleaseError{Cause error}` | Matches `ErrReleasedWithoutWipe`; `Unwrap` reaches the `mprotect` refusal. |

A nil `*Memory`, or a zero `Memory`, is a valid receiver for every method: not
alive, borrows fail with `ErrEnclaveDestroyed`, `Destroy` returns `nil`. Use
`*Memory`. A copied `Memory` value is a second handle on the same state, so
`Destroy` through either destroys both; `go vet` (copylocks) flags the copy.

There is no accessor that hands out a slice past the lock, and no string
constructor: a string source cannot be wiped. Removed identifiers and their
replacements are in [Upgrading](../README.md#upgrading).

## Invariants

1. **No failure touches another enclave.** A construction failure rolls back
   only its own mapping and returns a typed error; if the kernel refuses that
   rollback, the mapping goes to the orphan ledger for `WipeAll` to retry
   rather than being dropped. No failure path unmaps or wipes any other
   enclave — only that enclave's `Destroy`, or an explicit `WipeAll`, does.
2. **Constructors wipe or preserve their source exactly as documented** —
   `NewMemory` wipes on every path including refusal; `NewMemoryCopy`
   never writes `src`.
3. **Borrows are safe against `Destroy`, `Freeze` and `WipeAll`.** Each of those
   needs the write lock (the sweep only `TryLock`s it), so pages are never
   wiped, re-protected or unmapped under a `WithBytes`, `EqualTo`, `Size` or
   `IsAlive`. Every read is a borrow; no accessor hands out a slice past it.
4. **Inside a borrow**, `fn` must not call any method on the same enclave
   (nested `Destroy`/`Freeze` deadlock; a nested read deadlocks once a writer is
   waiting). `fn` may construct, borrow and destroy **other** enclaves.
5. **Frozen means fault-on-write.** Move- and copy-constructed enclaves are
   frozen before they are returned; sized enclaves are writable until `Freeze`
   succeeds. A refused `Freeze` leaves the enclave alive and writable.
6. **The handle is dropped exactly when the pages are gone.** A refused unlock
   or unmap keeps the mapping, the ledger entry and any `Allocator` reservation;
   `Destroy` again resumes where the last attempt stopped (the wipe, the canary
   check and a successful unlock are not repeated; see Platform contract for
   why the unlock must not be).
7. **"Wiped but held" reads as destroyed.** Once the wipe has run, every
   accessor (`WithBytes`, `EqualTo`, `Size`, `IsAlive`, `String`, `Freeze`) reports the enclave destroyed even if its
   pages are still held; `Destroy` retries the release. Such a mapping holds
   zeroes and its guard pages are already read-write, so reading it would hand
   back an unguarded all-zero "key".
8. **A construction racing `WipeAll` can return an already-destroyed enclave**
   (swept between publication and return). It behaves as destroyed; callers
   that construct during shutdown must check.

## Error semantics

| Error | Returned by | Meaning / fail-closed behavior |
|---|---|---|
| `ErrEmptyEnclave` | `NewMemory`, `NewMemoryCopy` | Zero-length material; nothing mapped. |
| `ErrInvalidSize` | `NewMemorySized` | `n <= 0` or too large to map (data + two guard pages overflow `int`); decided before `mmap`. |
| `ErrLockedMemoryUnavailable` (`*LockedMemoryError`) | constructors, `Freeze`, `Destroy` | Kernel refused `mmap`/`mlock`/`madvise`/`mprotect`/`munlock`/`munmap`. From `Destroy` it means the release was refused and the pages are held (retry by calling `Destroy` again) **only if the error does not also match `ErrReleasedWithoutWipe`** — see below. |
| `ErrEnclaveDestroyed` | `WithBytes`, `EqualTo`, `Freeze` | Material gone (destroyed, swept, or wiped-but-held). |
| `ErrNilFunc` | `WithBytes` | `fn` is nil on a live enclave; nothing is borrowed. |
| `ErrReleasedWithoutWipe` (`*UnwipedReleaseError`) | `Destroy`; `NewMemory`/`NewMemoryCopy` (carried with a freeze failure in its rollback's `*CleanupError`); `Allocator.New` likewise | `mprotect` denied, pages handed back with a bare `munmap` and **released**. They were locked for their whole life (never swapped) and the kernel zeroes anonymous pages before reuse, but the in-process wipe did not run. |
| `ErrEnclaveCorrupted` | `Destroy`; also counted by the next `WipeAll` | Canary or guard mismatch. See below. |
| `ErrCoreDumpLimitUnsupported` | `CoreDumpsDisabled` | Windows: no process-wide core-dump limit exists. |
| `ErrCoreDumpLimitNotApplied` | `CoreDumpsDisabled` | `HardenProcess` has not run; importing the package leaves `RLIMIT_CORE` alone. |
| `ErrCoreDumpLimitFailed` (`*CoreDumpLimitError`) | `CoreDumpsDisabled`; `HardenProcess` (as its `Cause`) | `setrlimit(RLIMIT_CORE)` refused, or the read-back is not 0/0. |
| `ErrProcessHardeningUnsupported` | `HardenProcess` | Windows: neither step exists, nothing applied. |
| `ErrProcessHardeningFailed` (`*ProcessHardeningError`) | `HardenProcess` | `PR_SET_DUMPABLE` or the `RLIMIT_CORE` step refused, or its read-back disagrees; the steps that took are still reported. |

Every sentinel and error type is declared in [errors.go](../../errors.go).
`LockedMemoryError`, `UnwipedReleaseError`, `ProcessHardeningError` and the
other cause-carrying types share one shape: a single `Cause error` field, a
message of the sentinel's text followed by `": "` and the cause, `Is` matching
that sentinel only, and `Unwrap` returning `Cause`. Where a failure and an
independent cleanup failure happen together (a refused rollback, a refused
unlock), the error is a `*CleanupError` carrying the failure and each refusal,
so it matches all of them and `ErrCleanupFailed`. The package builds no
`errors.Join`.

### `ErrReleasedWithoutWipe` and `ErrLockedMemoryUnavailable` are disjoint on release

A release has two failure outcomes, and each matches exactly one sentinel:

- **Released without the wipe** (`mprotect` denied, pages unmapped):
  `ErrReleasedWithoutWipe` only. `*UnwipedReleaseError.Cause` is the raw
  operating-system failure (an `*os.SyscallError` carrying the errno), not a
  `*LockedMemoryError`, precisely so the error does not also read as "pages
  still held" ([mapping.go](../../mapping.go), `release`).
- **Refused** (pages still held): `ErrLockedMemoryUnavailable` only.

Only a **frozen** enclave reaches the unwiped path with its material intact:
release wipes a writable data region before the `mprotect`, with no syscall
that can be refused, while a read-only region cannot be overwritten without
the denied `mprotect`. A writable enclave whose `mprotect` is refused was
already wiped, so it is released and `Destroy` returns `nil`. Under a permanent denial (seccomp), keeping the mapping
would leave the material resident for the process lifetime, so it is unmapped.

A **constructor** failure is different: a refused freeze always matches
`ErrLockedMemoryUnavailable` (the construction failed), and when its rollback
took the unwiped path the rollback's `ErrReleasedWithoutWipe` is carried with it in a `*CleanupError`, so
that one error matches both. Testing `ErrReleasedWithoutWipe` first classifies
every case correctly:

```go
err := e.Destroy()
switch {
case err == nil:
case errors.Is(err, enclave.ErrReleasedWithoutWipe):
	// Released; the wipe was skipped because mprotect is denied.
case errors.Is(err, enclave.ErrLockedMemoryUnavailable):
	// Refused; pages still held. Destroy again later retries.
}
```

### Canary corruption

`Destroy` returns an error matching `ErrEnclaveCorrupted` when the canary
fails, **after** wiping the material, releasing the pages and returning any
reservation. If the kernel refuses the release in the same attempt, the error
matches both `ErrEnclaveCorrupted` and `ErrLockedMemoryUnavailable`, the pages
are kept, and the retry that releases them reports the corruption again
(detection is sticky). Every corruption `Destroy` detects is also recorded for
the next admitted `WipeAll`, which counts it in `SweepError.Corrupt` once per
enclave, so a `defer e.Destroy()` that discards the error does not lose it.

The package does not panic. Whether a process with overwritten key memory
should stop is the caller's decision.

## Platform contract

| GOOS | Lock primitive | Per-mapping dump exclusion (verified) | Fork exclusion (verified) | `CoreDumpsDisabled()` after `HardenProcess` | Notes |
|---|---|---|---|---|---|
| linux, android | `mlock` | `MADV_DONTDUMP` (refusal fails the allocation) | `MADV_DONTFORK` on the whole mapping (refusal fails the allocation) | `setrlimit(RLIMIT_CORE, 0/0)` result | The only GOOS whose tests run ([test status](#test-status)). |
| freebsd, dragonfly | `mlock` | `MAP_NOCORE` + `MADV_NOCORE` (madvise refusal fails the allocation) | none: x/sys exposes no `minherit` | setrlimit result | |
| openbsd | `mlock` | `MAP_CONCEAL` on the `mmap` itself | none: x/sys exposes no `minherit`, and raw syscalls are refused | setrlimit result | |
| darwin, ios, netbsd | `mlock` | none exposed by x/sys | none | setrlimit result | `RLIMIT_CORE` is the only control. |
| aix, solaris, illumos | `mlock` | none exposed by x/sys | none | setrlimit result | `mlock` needs a privilege an ordinary process lacks: unprivileged processes get `ErrLockedMemoryUnavailable` from every allocation. |
| windows | `VirtualLock` | none (WER API deliberately unused) | n/a (no fork) | `ErrCoreDumpLimitUnsupported` | Dump exposure must be governed by host policy (WER `LocalDumps`, who may open the process). |
| anything else | — | — | — | — | Does not compile. |

### Test status

Linux is the only platform whose tests run. For v0.9.0-rc.1 the BSDs (freebsd,
openbsd, netbsd, dragonfly) and Windows are **build-only**: `make cross-build`
compiles and vets them and nothing executes, so their rows above describe what
the code does, not behavior a test has observed. Test runners for them come in
a later release. darwin, iOS, illumos, Solaris, AIX and Android are likewise
compiled, not run (iOS is not in the matrix; it builds through the darwin
files).

**Why `MADV_DONTFORK`, not `MADV_WIPEONFORK`.** Both keep the material out of a
forked child. `WIPEONFORK` leaves the range mapped and zero-filled in the child,
so code there that still holds the enclave reads an all-zero buffer it can
mistake for a key; `DONTFORK` removes the range, so the same read faults. The
fault is the fail-closed outcome. `DONTFORK` has existed since Linux 2.6.16, so
a refusal is a denial and fails the allocation, with no "kernel too old"
`EINVAL` to fall back from. Go's own `os/exec` on Linux spawns with
`CLONE_VM|CLONE_VFORK` and never copies the address space, so this binds
`fork(2)` from cgo or C libraries and the copying clone Go uses when a child
gets a new user namespace.

**`RLIMIT_CORE` vs piped `core_pattern`.** A zero `RLIMIT_CORE` stops the kernel
writing core *files*. On Linux a `core_pattern` beginning with `|`
(systemd-coredump, apport) is not bound by `RLIMIT_CORE` (core(5)); there,
`MADV_DONTDUMP` — applied by the kernel's dump writer whatever the destination —
is what keeps enclave pages out. Heap copies (see
[sealing](../sealing/engineering.md#key-schedule-heap-exposure)) are not covered.
`HardenProcess` lowers `RLIMIT_CORE` soft *and* hard, so no other code in an
unprivileged process can raise it back.

**A missing control is dropped, not fatal.** Where a platform lacks a
per-mapping dump or fork exclusion, that step is a no-op reporting success:
refusing every allocation would also remove the lock, guard pages and canary.
Where the exclusion exists (Linux, FreeBSD, DragonFly), a refusal fails the
allocation, since the control is known to work and was denied. FreeBSD and
DragonFly verify with `MADV_NOCORE` because a `MAP_NOCORE` the kernel ignored
would leave nothing to notice.

**Why no WER exclusion on Windows.** `WerRegisterExcludedMemoryBlock` removes a
block from Windows Error Reporting reports only; `MiniDumpWriteDump` from
another process still captures it. Each enclave is its own reservation, so
each would need its own entry, and entries come from a per-process pool capped
at `WER_MAX_REGISTERED_ENTRIES` (512) shared with every other WER registration
in the process. Failing closed would make the 513th live enclave (or fewer, if
a crash-reporting SDK holds entries) fail with `ErrLockedMemoryUnavailable`, a
limit invisible to `Allocator` budgets that also starves other libraries'
registrations. Registering best effort would make the exclusion silently
partial. Neither is acceptable, so none is attempted.

**One syscall per primitive.** The `sys*` functions in `osmem_*.go` each make
exactly one system call, with no hidden wipe, protection change or advice, so
`mapping.go` owns every step's order and failure policy and the release path
has a single unmap. `VirtualUnlock` refuses pages that are not locked (unlike
`munlock`), so release unlocks at most once per mapping. An unsupported GOOS
(js, wasip1, plan9) fails to compile with an error naming the reason.

**One implementation per concern per GOOS.** The platform layer is five
concerns, each a set of files named `<concern>_<platform>.go`. A build compiles
exactly one implementation of each:

| Concern | Files | Catch-all |
|---|---|---|
| `osmem`: mmap, mlock, mprotect primitives and the protection table | `_unix` (aix, darwin, dragonfly, freebsd, linux, netbsd, openbsd, solaris), `_windows` | `_unsupported`: fails to compile |
| `madvise`: dump and fork exclusion, `coreDumpMapFlags` | `_linux`, `_bsd` (dragonfly, freebsd), `_openbsd` | `_unsupported`: darwin, netbsd, aix, solaris, windows; the hooks are no-ops |
| `memlock`: ceiling discovery | `_linux`, `_bsd` (darwin, dragonfly, freebsd, netbsd, openbsd) | `_unsupported`: aix, solaris, windows; reports `LimitUnsupported` |
| `harden`: the non-dumpable step of `HardenProcess` (`harden.go` runs the steps; the `RLIMIT_CORE` step is `osmem`'s) | `_linux` | `_unsupported`: the step is `ErrProcessHardeningUnsupported` |
| `secret`: key-schedule erasure | `secret_erase.go` (linux, amd64 or arm64, `GOEXPERIMENT=runtimesecret`) | `secret_noerase.go` |

`_unsupported` is the only catch-all; its build constraint is the exact
complement of the named files. `_unix` holds code the named platforms share
(`madvise_unix.go`, `memlock_unix.go`) and compiles exactly where a named
platform file does. `madvise_<platform>.go` states only constants (the advice
for core dumps and fork, and the mapping-time flag), and `madvise_unix.go`
makes the one `madvise` call. `_bsd` states its members in its constraint and
doc: `memlock_bsd.go` includes darwin, `madvise_bsd.go` does not. The `secret`
files keep their names because the Makefile's `test-runtimesecret` target
checks them. `TestPlatformLayer_EveryGOOSHasExactlyOneImplementation` holds
every concern to this for every GOOS, and `make cross-build` compiles each one.

## Configuration

None. No environment variables or options, and importing the package changes
no process state.

`HardenProcess` holds the process-wide steps, which are the binary's choice and
never run at import. Lowering `RLIMIT_CORE` to zero, soft and hard, is
inherited across `fork` and `execve`, so every child process the binary starts,
go-enclave user or not, also starts with `RLIMIT_CORE` 0 and cannot raise it
without privilege. Marking the process non-dumpable breaks same-uid debuggers,
profilers and crash collectors, and makes `/proc/<pid>` files root-owned.
Neither is a library's to decide for the program that imports it. Constructors
do not consult the result.

## Persistence

None. Enclaves live and die with the process.

## Test strategy

- **Unit tests** in the root package, run with `-race` across `-cpu=1,2,8`
  (`make test`, `make coverage` with a 90% floor).
- **Fault injection** through package-private seams that production code never
  reassigns: `lockMemory`, `unlockMemory`, `protectMemory`, `unmapMemory`,
  `excludeCoreDump`, `excludeFork`, `fillCanary`
  ([mapping.go](../../mapping.go)) model a refused `mlock`, `munlock`,
  `mprotect`, `munmap`, dump or fork `madvise`, and canary fill. Every step of
  `newMapping` is failed in turn and its rollback asserted, including the
  orphan ledger when the rollback's `munmap` is refused too. A strict unlock
  seam emulates Windows' refusal to unlock unlocked pages, so retries are
  proven never to unlock twice. Linux-only tests lower `RLIMIT_MEMLOCK` in a
  subprocess, and FAIL — never skip — where the environment refuses the
  change; the suite states its requirement (soft limit at least 2 MiB, hard
  limit at least 2 MiB when `CAP_IPC_LOCK` exempts the soft one) and checks it
  once at startup. Those subprocesses drop `CAP_IPC_LOCK` on a pinned thread
  (capabilities are per thread) and need `getrlimit`, `setrlimit` and `capset`
  unfiltered.
- **Dump and fork exclusion** are checked against the kernel: `madvise`
  refuses an unaligned address, so tests prove `excludeFromCoreDump` and
  `excludeFromFork` report a refusal as an `*os.SyscallError`, and a fresh
  mapping's `/proc/self/smaps` `VmFlags` must show `dc` on every page and `dd`
  on the data region (`lo` = `VM_LOCKED`, `dd` = `VM_DONTDUMP`, `dc` =
  `VM_DONTCOPY`). The integration suite checks `dc` on every enclave and
  its guards, and refuses each `madvise` (and `HardenProcess`'s `prctl`) with a
  seccomp `SECCOMP_RET_ERRNO` filter to prove construction fails closed. The
  kernel may merge adjacent `PROT_NONE` guard VMAs, so a guard VMA can exceed
  one page.
- **Residue sweeps** search process memory for test material after a wipe.
  They need an unfiltered `/proc`, must scan anonymous mappings the kernel has
  named (such as `[anon: Go: heap]`), and wipe their own scan buffer so a later
  sweep cannot find an earlier sweep's copy. Test material lives in locked pages
  or on the heap, never in stack locals: stack growth copies the old stack and
  frees it unwiped, leaving false residue.
- **User namespaces**: a test re-executes the binary as root of a new user
  namespace (the `unshare -Ur` case) and asserts `RLIMIT_MEMLOCK` is reported
  enforced and `mlock` past it fails. It fails, never skips, when the host
  refuses unprivileged user namespaces or grants one without capabilities. It
  is built with the `userns` tag, which the default toolchain container's
  seccomp profile cannot run, so `make integration-test-userns` (part of every
  `integration-test-enclave` and of `integration-test-locked-memory-budget`)
  runs it in the `userns` compose service, whose profile permits
  `CLONE_NEWUSER`.
- **`HardenProcess`** runs in a subprocess, read back with `PR_GET_DUMPABLE`
  and `getrlimit(RLIMIT_CORE)`; each step is also refused through a seam.
  Subprocess and parent-side tests pin that importing the package leaves the
  process dumpable and its `RLIMIT_CORE` unchanged.
- **Construction rollback** is measured against the kernel: in a subprocess,
  `NewMemory`, `NewMemoryCopy` and `Allocator.New` fail at `mlock` (a real
  `RLIMIT_MEMLOCK` ceiling) and at the freeze, and `VmLck`, `InUse` and the
  shutdown ledger must return to their starting values.
- **Cross-compilation** of the `CROSS_TARGETS` matrix in the Makefile
  (`make cross-build`; Android and iOS, which build through the linux and
  darwin files, are not in it);
  only Linux executes tests.
- **FIPS strict-mode compatibility** (`make test-fips`): the package builds and
  passes under `GOFIPS140=latest GODEBUG=fips140=only`. That is not a
  validation claim; see [sealing](../sealing/engineering.md#fips-140-3).
- **Integration**: `make integration-test-enclave` runs `test/integration/enclave`
  in the project devcontainer's `integration` stage and fails, rather than
  passes, when either is absent. That stage shares its `base` stage (Go,
  gcc/musl-dev, module and build caches) with the `toolchain` stage
  (`build/docker/devcontainer/Dockerfile`), the image every other gate passes
  in (`make docker-run CMD='make coverage'`), and ships none of its tools. The test that importing leaves `RLIMIT_CORE` unchanged is meaningful
  there because the devcontainer starts with a non-zero core limit and the
  test's parent (`go`) does not import go-enclave.
- **Borrow benchmarks** (`BenchmarkBorrow*`, `BenchmarkIsAliveParallel`) are
  compared with `benchstat` around changes to the borrow path; there is no CI
  threshold.

## Observability

No logs, metrics or global hooks. Everything observable is a return value:
constructor and `Destroy` errors, `IsAlive`, `Size`, `CoreDumpsDisabled`, and the
`WipeAll` count and `*SweepError`.

# go-enclave documentation

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-11-12
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

What go-enclave is and every feature it has: [SPEC](SPEC.md). What is done
and what comes next: [ROADMAP](../ROADMAP.md). The generated API reference is
on [pkg.go.dev](https://pkg.go.dev/github.com/jeremyhahn/go-enclave).

Each feature has one folder with four pages: `user.md` (task-oriented usage),
`api.md` (the Go API), `architecture.md` (design, boundaries, rejected
alternatives) and `engineering.md` (exported surface, invariants, errors,
tests). A folder may also hold a design or a proposal beside them. There is
no CLI: this is a library ([interfaces](SPEC.md#interfaces)).

Platforms: tests run on Linux only. The BSDs and Windows are build-only: they
compile and their test binaries link, and no test runs on them
([test status](memory-enclave/engineering.md#test-status)).

## Features

| Feature | Pages | What it covers |
|---|---|---|
| memory-enclave | [user](memory-enclave/user.md) · [api](memory-enclave/api.md) · [architecture](memory-enclave/architecture.md) · [engineering](memory-enclave/engineering.md) | The memory enclave, held as a `ByteAccess`: constructors, borrowing, `Freeze` through `As`, `Destroy` and canary corruption, guard pages and canary, platform and core-dump matrix |
| locked-memory-budget | [user](locked-memory-budget/user.md) · [api](locked-memory-budget/api.md) · [architecture](locked-memory-budget/architecture.md) · [engineering](locked-memory-budget/engineering.md) | `Allocator`, `RLIMIT_MEMLOCK` discovery, retuning, the process allocator, refunds for failed constructions |
| sealing | [user](sealing/user.md) · [api](sealing/api.md) · [architecture](sealing/architecture.md) · [engineering](sealing/engineering.md) | `Sealed`, `Sealer` modes, the `KeyProtector`/`RootUnsealer` seam, contexts, `Openable`, FIPS, the key-schedule heap exposure and its erasure under `runtime/secret` |
| keyprotector-providers | [hardware providers](sealing/hardware-providers.md) | The TPM 2.0 provider (`backends/tpm`) as shipped, and the outline of the secure-element (PKCS#11) provider with its open questions. Installing a hardware provider: [sealing user guide](sealing/user.md#install-a-hardware-provider) |
| shutdown-sweep | [user](shutdown-sweep/user.md) · [api](shutdown-sweep/api.md) · [architecture](shutdown-sweep/architecture.md) · [engineering](shutdown-sweep/engineering.md) | `WipeAll(ctx)`: admission, waiting for borrows, termination, the count and `SweepError` |
| provider-conformance | [user](provider-conformance/user.md) · [api](provider-conformance/api.md) · [architecture](provider-conformance/architecture.md) · [engineering](provider-conformance/engineering.md) | `providertest.TestProvider(ctx, cfg)` for `KeyProtector` and `RootUnsealer` authors |
| backends | [user](backends/user.md) · [api](backends/api.md) · [architecture](backends/architecture.md) · [engineering](backends/engineering.md) | The backend seam: `Handle`, `Backend`, capabilities, the named registry, `As`, the sealing wiring (`WithBackend`, `OpenIn`, `SealFrom`) |
| backend-conformance | [user](backend-conformance/user.md) · [api](backend-conformance/api.md) · [architecture](backend-conformance/architecture.md) · [engineering](backend-conformance/engineering.md) | `backendtest`: the conformance suite for `Backend` and `Handle` authors |
| backend-detection | [user](backend-detection/user.md) · [api](backend-detection/api.md) · [architecture](backend-detection/architecture.md) · [engineering](backend-detection/engineering.md) | `Detect(ctx)`: the `Prober` rank and probe, selecting the most secure usable registered backend with locked memory as the floor, and why each other was passed over |
| linux-secretmem | [user](linux-secretmem/user.md) · [api](linux-secretmem/api.md) · [architecture](linux-secretmem/architecture.md) · [engineering](linux-secretmem/engineering.md) | `NewSecretMemory`: a Linux-only backend of rank 1 on `memfd_secret(2)` memory, out of the kernel direct map; what it adds over the memory enclave, kernel requirements, its probe and failure modes. Also covers open-in-secretmem |
| arm-trustzone | [design](backends/arm-trustzone-design.md) · [user](backends/user.md#arm-trustzone) · [engineering](backends/engineering.md#arm-trustzone) | The backend over OP-TEE in the nested module `backends/armtrustzone`, and its `KeyProtector` |

### Nested modules

Each is its own Go module and requires the root module, never the reverse.

| Module | Docs |
|---|---|
| `github.com/jeremyhahn/go-enclave/backends/tpm` | [pkg.go.dev](https://pkg.go.dev/github.com/jeremyhahn/go-enclave/backends/tpm), [hardware providers](sealing/hardware-providers.md#tpm-provider) |
| `github.com/jeremyhahn/go-enclave/backends/armtrustzone` | [pkg.go.dev](https://pkg.go.dev/github.com/jeremyhahn/go-enclave/backends/armtrustzone), [arm-trustzone design](backends/arm-trustzone-design.md) |

### Backend proposals

Designs for future backends. None is implemented; each is a starting point for
its [ROADMAP](../ROADMAP.md#future) row.

| Proposal | Backend |
|---|---|
| [amd-sev](backends/amd-sev.md) | AMD SEV-SNP confidential VMs |
| [intel-tdx](backends/intel-tdx.md) | Intel TDX trust domains |
| [imx-edgelock-enclave](backends/imx-edgelock-enclave.md) | NXP i.MX 95 EdgeLock Secure Enclave |
| [nvidia-blackwell](backends/nvidia-blackwell.md) | NVIDIA Blackwell confidential computing |

### Project

| Page | What it covers |
|---|---|
| [build and release](build-and-release.md) | How a change is built and gated, and how a signed release is cut, verified and published |
| [integration coverage](../test/integration/COVERAGE.md) | Which integration test covers which feature |
| [reference](reference/README.md) | The standards the code implements, copied and indexed by implementing symbol |

## Upgrading

This is the only place migration guidance is written; each feature's `user.md`
and `api.md` link here. The module is pre-1.0: a breaking change lands in a
MINOR bump, and its [CHANGELOG.md](../CHANGELOG.md) entry is marked
**BREAKING** and links here. Upgrade one release at a time. Each section
describes its release under the names that release shipped.

Releases after v0.9.0-alpha need no source change. Check the minimum Go
version in `go.mod`, which security releases of the toolchain raise.

### v0.9.0-alpha (from v0.8.0-alpha)

#### Renames

The package name already says "enclave", so the types drop the suffix. There
are no deprecated aliases; rename with a search and replace.

| v0.8 | v0.9 |
|---|---|
| `MemoryEnclave` | none: hold `ByteAccess` ([below](#constructors-return-interfaces)) |
| `NewMemoryEnclave`, `NewMemoryEnclaveCopy`, `NewMemoryEnclaveSized` | `NewMemory`, `NewMemoryCopy`, `NewMemorySized` |
| `SealedEnclave` | `Sealed` |
| `(*SealedEnclave).OpenWith(ctx, a)` | `Sealed.OpenIn(ctx, a)` |
| `providertest.AbortedError.Err` | `providertest.AbortedError.Cause` |

#### Constructors return interfaces

Every constructor hands out an interface, never a pointer to a concrete type.
`Sealed`, `Allocator` and `SoftwareProvider` keep their names but are now
interfaces; their implementations are internal.

| Function (v0.9 name) | v0.8 returned | v0.9 returns |
|---|---|---|
| `NewMemory`, `NewMemoryCopy`, `NewMemorySized` | `*MemoryEnclave` | `ByteAccess` |
| `NewSealed`, `NewSealedFrom`, `Sealer.Seal`, `Sealer.SealFrom` | `*Sealed` | `Sealed` |
| `Sealed.Open` | `*MemoryEnclave` | `ByteAccess` |
| `NewAllocator`, `NewAllocatorWithinRLimit`, `ProcessAllocator` | `*Allocator` | `Allocator` |
| `Allocator.New`, `Allocator.NewSized` | `*MemoryEnclave` | `ByteAccess` |
| `NewSoftwareProvider` | `*SoftwareProvider` | `SoftwareProvider` |

`SetAllocator` and `Allocator.TransferTo` take an `Allocator`. Replace
`*enclave.Sealed`, `*enclave.Allocator` and `*enclave.SoftwareProvider` in
declarations with the interface name, and `*enclave.MemoryEnclave` with
`enclave.ByteAccess`. A failed call returns a nil interface, so `x == nil`
checks are unchanged.

- **`enclave.Memory` is gone.** The type behind a memory enclave is internal;
  hold the `ByteAccess` its constructors, `Sealed.Open` and `Allocator.New`
  return, and use `As` for `Freeze`, below. A nil or zero enclave can no
  longer be declared.
- **Freeze through `Freezer`.** `ByteAccess` has no `Freeze`; reach it with
  `As`:

  ```go
  // v0.8
  err := e.Freeze()

  // v0.9
  var f enclave.Freezer
  if !enclave.As(e, &f) { return errors.New("not freezable") }
  err := f.Freeze()
  ```

- **`String` and `GoString` are not interface methods.** Printing with `%v`,
  `%s` or `%#v` is still redacted; replace a direct `s.String()` call on a
  `Sealed` with `fmt.Sprint(s)`.
- **Only this package's `Allocator` is accepted.** `SetAllocator` and
  `TransferTo` refuse another implementation (a wrapper or a test fake) with
  `ErrAllocatorNotConstructed`; nil is still `ErrNilAllocator` and
  `ErrInvalidTransfer`. A nil `Allocator` given to `Sealed.OpenIn` is a nil
  `Backend` and returns `ErrInvalidBackend`, was `ErrNilAllocator`.
- **`Sealer` is an interface.** `*enclave.Sealer` becomes `enclave.Sealer`:
  `NewSealer` returns it and `SetSealer` takes it. Callers drop the `*`, and
  nothing else changes. `SetSealer` refuses another implementation with
  `ErrSealerNotConstructed` and a typed-nil one with `ErrNilSealer`; with no
  zero `Sealer` to declare, `Seal` and `SealFrom` no longer return
  `ErrSealerNotConstructed` or `ErrNilSealer`.
- **Zero values and nil receivers are gone.** No caller can declare a zero
  `Sealed`, `Allocator` or `SoftwareProvider` any more, so
  `ErrProviderNotConstructed` and a zero `Allocator{}`'s
  `ErrAllocatorNotConstructed` no longer reach callers. Calling a method on a
  nil interface panics, as for any Go interface.

#### Memory enclave

**Importing the package no longer lowers `RLIMIT_CORE`; `HardenProcess` does.**
A library changing a process-wide limit at import was the binary's
decision taken without it. Until `HardenProcess` runs, `CoreDumpsDisabled`
returns `ErrCoreDumpLimitNotApplied`, so code that required it to be `nil`
must call `HardenProcess` first:

```go
// v0.8: importing lowered the limit
if err := enclave.CoreDumpsDisabled(); err != nil { return err }

// v0.9
if _, err := enclave.HardenProcess(); err != nil { return err }
if err := enclave.CoreDumpsDisabled(); err != nil { return err }
```

`HardenProcess` now lowers the limit everywhere but Windows (it returned
`ErrProcessHardeningUnsupported` off Linux) and also marks the process
non-dumpable on Linux, as before; `ProcessHardening.CoreDumpsDisabled` reports
the new step, and its failure is a `*ProcessHardeningError` whose `Cause` is a
`*CoreDumpLimitError` (`ErrCoreDumpLimitFailed`). A binary that wants only the
core limit, not the non-dumpable flag, must now weigh both.

**`Destroy` of a writable enclave whose `mprotect` is refused returns `nil`**,
not `ErrReleasedWithoutWipe`: its data was wiped before the `mprotect`, so
nothing was released unwiped. Only a frozen enclave reports it.

#### Locked-memory budget

**`Allocator` values share their state.** A copied value was a second,
independent budget that could admit the same headroom twice. A copy now
reaches the same budget, and `go vet` reports it. Build an `Allocator` with
`NewAllocator` and pass the interface it returns.

#### Sealing

**`OpenIn` takes a `Backend` and returns a `Handle`.** An `Allocator` is a
`Backend`, so a budgeted open keeps its argument; reach the bytes through
`ByteAccess` with `As`, or open with `DefaultBackend()` where you only wanted
`Open`:

```go
// v0.8
e, err := s.OpenWith(ctx, a)

// v0.9
h, err := s.OpenIn(ctx, a)
if err != nil { return err }
var e enclave.ByteAccess
if !enclave.As(h, &e) { return errors.New("no byte access") }
```

**Re-sealing an opened value seals from the handle.** `NewSealed(ctx, b)`
inside `e.WithBytes` used to crash on the read-only pages; it now fails with
`ErrSealSourceReadOnly`. Use `NewSealedFrom(ctx, e)`, which leaves `e`
intact.

**`Sealer` and `Sealed` values share their state too**, as `Allocator`
does above. Pass the `Sealer` and `Sealed` interfaces.

**`SetSealer` refuses a destroyed `Sealer`** with `ErrSealerDestroyed`, and
**`NewSealer` refuses a nil option** with `ErrInvalidSealerOption`.

#### Errors

**No failure is an `errors.Join` composite any more**. Where an
operation's failure came with cleanup that also failed, or a release refused
more than once, the error is a `*CleanupError` (`ErrCleanupFailed`): `Failure`
is the operation's own error and `Causes` each refusal. Every `errors.Is` and
`errors.As` match on what it carries still holds; code that tested the error
for `Unwrap() []error` should use `errors.As` with `*CleanupError` instead.
`providertest.TestProvider` returns a `*FindingsError` whose `Findings` are the
run's findings, where it returned a join.

The cause- and name-carrying error types are defined types, no longer aliases
of a generic one, so `go doc` shows their fields and methods. Struct literals,
`errors.Is` and `errors.As` are unchanged.

### v0.8.0-alpha (from v0.7.0-alpha)

#### Memory enclave

**`EqualTo` returns `(bool, error)`; `EqualToErr` is gone.**

```go
// v0.7
if e.EqualTo(x) { grant() }
ok, err := e.EqualToErr(x)

// v0.8
ok, err := e.EqualTo(x)
if err != nil { return err } // ErrEnclaveDestroyed
if ok { grant() }
```

**`Destroy` returns `ErrEnclaveCorrupted` instead of panicking.** Remove any
`recover` around `Destroy`; check the error, or rely on the next `WipeAll`,
which reports every corruption `Destroy` detected since the previous sweep.

**`Open`, `OpenString` and `NewMemoryEnclaveFromString` are removed**.
`Open`'s slice outlived the lock, so a concurrent `Destroy` or `WipeAll`
unmapped it under its reader. Move readers to `WithBytes` and string sources to
`NewMemoryEnclave([]byte(...))`:

```go
// v0.7
view, err := e.Open()
s, err := e.OpenString()
e, err := enclave.NewMemoryEnclaveFromString(secret)

// v0.8
err := e.WithBytes(func(view []byte) error { return use(view) })
err := e.WithBytes(func(b []byte) error { return useString(string(b)) })
e, err := enclave.NewMemoryEnclave([]byte(secret))
```

#### Locked-memory budget

`LimitError` is renamed `BudgetInUseError`; code that matches the
`ErrBudgetInUse` sentinel with `errors.Is` needs no change, and code using
`errors.As` changes the type name only. A nil `*Allocator` returns
`ErrNilAllocator` from every method that can fail, instead of panicking.

#### Sealing

**Typed provider options replace `WithProvider` and `WithMode`.** The option
now selects the mode, and `ErrProviderMode` and `ErrInvalidMode` are gone: a
mismatch no longer compiles.

```go
// v0.7
s, err := enclave.NewSealer(enclave.WithProvider(p), enclave.WithMode(enclave.ModePerOperation))
r, err := enclave.NewSealer(enclave.WithProvider(p)) // ModeRootKey

// v0.8
s, err := enclave.NewSealer(enclave.WithKeyProtector(p))
r, err := enclave.NewSealer(enclave.WithRootUnsealer(p))
```

A nil or typed-nil provider, or both options at once, returns
`ErrInvalidProvider`. `WithMode(ModePerOperation)` with no provider used a
software provider the sealer owned; pass one explicitly and destroy it
yourself:

```go
p := enclave.NewSoftwareProvider()
defer p.Destroy()
s, err := enclave.NewSealer(enclave.WithKeyProtector(p))
```

**`WithProviderHealth` is replaced by the `HealthReporter` interface.** Move
the callback onto the provider as a `Health() error` method; the sealer finds
it by type assertion.

```go
// v0.7
enclave.NewSealer(enclave.WithProvider(p), enclave.WithMode(enclave.ModePerOperation),
	enclave.WithProviderHealth(p.health))

// v0.8
func (p *MyProvider) Health() error { return p.health() }
enclave.NewSealer(enclave.WithKeyProtector(p))
```

**`(*SealedEnclave).Destroy` returns `error`**, like `MemoryEnclave.Destroy`
and `Sealer.Destroy`. It is always `nil`; a `defer s.Destroy()` still
compiles, and a method value passed as `func()` (for example
`t.Cleanup(s.Destroy)`) needs a wrapper.

#### Provider conformance

`TestProvider` fails closed. Off Linux, without locked memory, or with a
blind control, a residue sweep that cannot run used to be logged and return
`nil`; it now returns an error matching `ErrNotMeasured` (`*NotMeasuredError`)
unless `Config.SkipResidueSweep` is set with a reason. Every `providertest`
error message now starts with `providertest:`.

#### Errors

Every root sentinel and error type is declared in `errors.go`, and every
`providertest` one in `providertest/errors.go`.

- `LockedMemoryError.Cause` is an `error`, was `any`.
- `ProcessHardeningError` matches the new `ErrProcessHardeningFailed`.
- The cause-carrying types (`LockedMemoryError`, `UnwipedReleaseError`,
  `LimitDiscoveryError`, `ProcessHardeningError` and the sealing types) are
  aliases of one generic type with a `Cause error` field, rendering as the
  sentinel's text, `": "` and the cause. Struct literals and `errors.As`
  targets are unchanged.
- Seal and open failures are `*SealError` and `*OpenError`, not `errors.Join`
  composites. They match `ErrSealFailed` / `ErrOpenFailed` and unwrap to the
  cause, so every `errors.Is` match on the sentinels, `ctx.Err()`,
  `context.Cause` and the provider's error still holds. A sweep that meets a
  failure reports `*SealerWipedError`, matching `ErrSealerWiped`. Code that
  walked `Unwrap() []error` must use `errors.Is`/`errors.As`. A failure
  together with an independent cleanup failure is still joined, so it matches
  both.
- `BudgetError` and `BudgetInUseError` messages read `<N> bytes requested`,
  was `<N> requested`. Fields and matched sentinels are unchanged.
- `providertest.AbortedError` renders as `ErrAborted`'s text followed by the
  context's error; its `Err` field and matches are unchanged.

### v0.7.0-alpha (from v0.6.2-alpha)

#### Memory enclave

**`Destroy` returns the release report; `DestroyErr` is gone.**

```go
// v0.6
if err := e.DestroyErr(); err != nil { /* ... */ }
defer e.Destroy()

// v0.7
if err := e.Destroy(); err != nil { /* ... */ }
defer e.Destroy() // still compiles; still discards the report
```

Semantics are `DestroyErr`'s, with one correction: `nil`,
`ErrReleasedWithoutWipe` (released without the wipe), or
`ErrLockedMemoryUnavailable` (refused; retry by calling `Destroy` again).
**The two no longer overlap.** In v0.6 an unwiped release also matched
`ErrLockedMemoryUnavailable`, which reads as "pages still held" although they
were gone; in v0.7 it matches only `ErrReleasedWithoutWipe`, and
`UnwipedReleaseError.Cause` is the raw OS error rather than a
`*LockedMemoryError`. Code that treated `ErrLockedMemoryUnavailable` from
`Destroy` as "retry" no longer retries a release that already happened.

**`CoreDumpsDisabled()` on Windows returns `ErrCoreDumpLimitUnsupported`**
instead of `nil`. Code that treats any non-nil result as fatal now fails on
Windows; accept the sentinel deliberately if host policy covers dumps:

```go
if err := enclave.CoreDumpsDisabled(); err != nil &&
	!errors.Is(err, enclave.ErrCoreDumpLimitUnsupported) {
	return err
}
```

**Dependency change:** `github.com/awnumar/memcall` is no longer required; the
module depends only on `golang.org/x/sys`. Run `go mod tidy`. DragonFly now
compiles, and illumos, Solaris and AIX are supported.

#### Locked-memory budget

No source change. The budget API (`Allocator`, `SetAllocator`,
`ProcessAllocator`) is unchanged; two neighbors changed: `WipeAll()` became
`WipeAll(ctx)` and `OpenWith(a)` became `OpenWith(ctx, a)`.

#### Sealing

Every call that can reach a provider takes a `context.Context` first.

```go
// v0.6
s, err := enclave.NewSealed(data)
s2, err := sealer.Seal(data)
e, err := s.Open()
e2, err := s.OpenWith(alloc)

// v0.7
s, err := enclave.NewSealed(ctx, data)
s2, err := sealer.Seal(ctx, data)
e, err := s.Open(ctx)
e2, err := s.OpenWith(ctx, alloc)
```

Provider implementations gain a context on every method and must honor it:

```go
// v0.6
func (p *MyProvider) Protect(key []byte) ([]byte, error)
func (p *MyProvider) Unprotect(blob, key []byte) error
func (p *MyProvider) UnsealRoot(dst []byte) error

// v0.7
func (p *MyProvider) Protect(ctx context.Context, key []byte) ([]byte, error)
func (p *MyProvider) Unprotect(ctx context.Context, blob, key []byte) error
func (p *MyProvider) UnsealRoot(ctx context.Context, dst []byte) error
```

Behavior changes to check for:

- A `ModePerOperation` provider's infrastructure error on open now arrives
  wrapped under the new `ErrOpenFailed` (still reachable with `errors.Is`/`As`).
  Code that matched only the provider's error keeps working; code that treated
  "anything not `ErrSealedAuthentication`" as one class can now match
  `ErrOpenFailed`.
- `(*SealedEnclave).Destroy` no longer waits for an `Open` in flight.
- **`Open` and `OpenWith` return a FROZEN (read-only) enclave**, like every
  constructor whose material is final. Reading through `WithBytes` is
  unchanged; a write into the opened plaintext now faults. Code that edited an
  opened value must copy it into its own `NewMemoryEnclaveSized` enclave
  inside the borrow. A refused freeze fails the open closed instead of
  handing back writable plaintext: no enclave is returned and the destination
  is wiped. `OpenWith`'s reservation is returned once the destination's pages
  are; if the kernel also refuses that release, the charge stays until a
  `WipeAll` reclaims them.
- A `ModeRootKey` sealer refuses a seal that would need a KEK generation past
  2^31 (the bound on its wrapping key, which each sealer derives from the
  root under its own salt) with an error matching both `ErrSealerExhausted`
  and `ErrSealFailed`. Existing values keep opening; new seals need a new
  `Sealer`, which derives a fresh wrapping key even over the same root. Only a
  very small `WithKEKRotationLimit` can reach it.
- New option `WithKEKRotationLimit(n)` sets a `ModeRootKey` KEK generation's
  crypto-period (1 to 2^31 wraps); out-of-range values, or the option with
  `ModePerOperation`, fail `NewSealer` with `ErrInvalidRotationLimit`.
- A sweep that destroys only one call's working key reports
  `ErrEnclaveDestroyed`; `ErrSealerWiped` is for a dead hierarchy key.

#### Shutdown sweep

```go
// v0.6
n, err := enclave.WipeAll()
if err != nil && errors.Is(err, enclave.ErrEnclaveCorrupted) { /* ... */ }

// v0.7
ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
defer cancel()
n, err := enclave.WipeAll(ctx)
var sweep *enclave.SweepError
if errors.As(err, &sweep) && sweep.Corrupt > 0 { /* ... */ }
```

- `WipeAll` takes a context; it bounds every wait (for borrows, contended
  locks, and admission behind another sweep). The fixed 200 µs × 8-pass backoff
  is gone: borrows are now waited for until they end or `ctx` does.
- Findings are a typed `*SweepError{Corrupt, Unwiped}`. `errors.Is` against
  `ErrEnclaveCorrupted` and `ErrReleasedWithoutWipe` still works; `errors.As`
  now exposes the counts.
- New `ErrSweepInProgress` when the call was not admitted. Treat it as "nothing
  swept", not as a finding.
- Under `context.Background()` a sweep, and a second `Background` caller
  queued behind it, now wait for the borrows they owe for as long as those
  take. Give shutdown a deadline.

#### Provider conformance

```go
// v0.6
err := providertest.TestProvider(providertest.Config{ /* ... */ })

// v0.7
err := providertest.TestProvider(t.Context(), providertest.Config{ /* ... */ })
```

`ErrAborted` and `AbortedError` are new. Your provider's methods also take a
context first (see Sealing above), and the suite now checks that they refuse
an already-ended one: a provider that passed under v0.6 but ignores its context
now fails.

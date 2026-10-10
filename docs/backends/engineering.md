# Backends — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-10
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

This contract covers the seam and its wiring into sealing: `WithBackend`,
`OpenIn`'s `Backend` parameter, `SealFrom` and `WithRequireKeyScheduleErasure`
are contracted in [sealing](../sealing/engineering.md#exported-surface). The
conformance suite `backendtest` is contracted in
[architecture.md](architecture.md#conformance-backendtest).

## Exported surface

| Identifier | Contract |
|---|---|
| `Handle` | The core of every backend's enclave: `Size`, `IsAlive`, `Destroy`, `Backend`. The dynamic type is a pointer; every method, the capabilities' included, is concurrency-safe and never panics on a live or destroyed handle. After `Destroy` every capability method that returns an error returns `ErrEnclaveDestroyed`; one without an error result (`AEAD`'s `NonceSize` and `Overhead`, `Public()`) keeps reporting its non-secret constant. A nil receiver is outside the contract. |
| `Backend` | The core of every backend: `Name`, valid and stable for the backend's life. A name is a registry and configuration label, not an instance identity. |
| `ByteAccess` | Handle capability: `WithBytes`, `EqualTo`, with `Memory`'s contract. |
| `Freezer` | Handle capability: `Freeze`, idempotent and irreversible. |
| `Deriver` | Handle capability: `Derive(ctx, info, n)` returns a new handle from the same backend. |
| `AEAD` | Handle capability: `NonceSize`, `Overhead`, and `Seal`/`Open` with `cipher.AEAD`'s arguments returning `([]byte, error)`: `ErrEnclaveDestroyed`, `ErrInvalidNonce`, `ErrAEADAuthentication` or the backend's own typed error, never a panic. |
| `Attester` | Handle or backend capability: `Attest(ctx, nonce)`, nonce 1 to 64 bytes, never truncated. |
| `Evidence{Format string; Data []byte}` | What `Attest` returned; this package never parses it. |
| `Importer` | Backend capability: `Import(ctx, material, opts...)` wipes `material` on every path; the handle follows the contract of the purpose `opts` name. |
| `Purpose`, `PurposeMaterial`, `PurposeWrappingKey`, `PurposeDataKey` | What imported material is for; each fixes the handle's contract ([architecture](architecture.md#importing-with-a-purpose)). |
| `Algorithm`, `AlgorithmAES256GCM` | The algorithm an imported key is for; follows the name rule. |
| `ImportSpec{Purpose; Algorithm}`, `ImportOption`, `WithPurpose`, `WithAlgorithm` | An import's resolved options; every import is transient. |
| `NewImportSpec(opts ...ImportOption) (ImportSpec, error)` | Applies `opts` in order; `ErrInvalidImport` for a nil option, a missing or unknown purpose, an algorithm on `PurposeMaterial`, or a key purpose without a valid algorithm. |
| `Sweeper` | Backend capability: `Sweep(ctx)` releases every handle and returns how many it could not. `ctx` bounds only waiting; a nil or done `ctx` still releases everything not held and is not an error. |
| `Confiner` | Backend capability: `ConfinesProcess()` reports, fixed for the backend's life and without blocking, whether this whole process runs inside the backend's boundary. |
| `Capability`, `CapabilityBytes` … `CapabilityConfine` | Names a capability in a `CapabilityError`; one constant per interface above and per standard opaque shape (`crypto.Signer`, `crypto.Decrypter`). |
| `LockedMemoryBackendName` | `"locked-memory"`: the default backend's name, always registered. |
| `DefaultBackend() Backend` | The locked-memory backend. |
| `Register(b Backend) error` | Adds `b` under `b.Name()`. Never rebinds a name. |
| `Lookup(name string) (Backend, error)` | The backend registered under `name`. |
| `BackendNames() []string` | Every registered name, sorted, the default included. |
| `As(v, target any) bool` | Sets `*target` to `v` when `v`'s dynamic type is assignable to it, else defers to `v`'s `As(any) bool` method. A nil or typed-nil `v` or a bad target returns `false` without panicking; a panic from `v`'s own `As` is not recovered. |
| `(*Memory).Backend() Backend` | The `*Allocator` that admitted the enclave, else `DefaultBackend()` (a nil enclave included); unchanged by `Destroy`. |
| `*Allocator` as `Backend` and `Importer` | Name `"locked-memory"`; `Import` is an admitted `New` that resolves `NewImportSpec` and refuses an `AlgorithmAES256GCM` key that is not 32 bytes with `ErrInvalidImport` ([budget](../locked-memory-budget/engineering.md)). Never registered. |
| `SweepError.Backends`, `BackendSweepFailure{Backend; Err}` | `WipeAll`'s backend phase: one entry per registered `Sweeper` that failed, in name order ([shutdown-sweep](../shutdown-sweep/engineering.md)). |
| `ErrBackendNotRegistered`, `BackendNotRegisteredError{Name}` | `Lookup` found no backend under `Name`. |
| `ErrBackendExists`, `BackendExistsError{Name}` | `Register` found `Name` taken. |
| `ErrInvalidBackend` | `Register` got a nil or typed-nil backend, or an invalid name; so did `WithBackend` and `OpenIn` for a nil or typed-nil one. |
| `ErrCapabilityUnsupported`, `CapabilityError{Backend; Capability}` | An operation needs a capability the handle or backend lacks. |
| `ErrInvalidImport` | `NewImportSpec` refused the options, or an `Importer` refused the material's length for the algorithm. |
| `ErrInvalidNonce`, `ErrAEADAuthentication` | An `AEAD` got a nonce that is not `NonceSize` bytes, or `Open` could not authenticate. |
| `ErrCleanupFailed`, `CleanupError{Failure; Causes}` | A handle the sealer no longer needed refused its `Destroy`, or cleanup failed alongside another failure; the sealer keeps a refusing handle for retry ([sealing](../sealing/engineering.md#error-semantics)). |

## Invariants

1. **No import-time state.** The registry starts holding the default backend as
   a static map entry; no `init` adds to it, and no backend module may register
   itself in its own `init`. `Register` is always the program's explicit call.
2. **A name is bound once.** `Register` refuses a taken name, the default's
   included, and there is no unregister, so a configuration that names a
   backend resolves to the same instance for the process's life. A name is a
   label, not an instance identity: `Lookup(h.Backend().Name())` returns the
   backend that made `h` only when the registered instance made it, never
   for an injected, unregistered backend or a budgeted `*Allocator`. A
   refused `Register` changes nothing.
3. **Backend code never runs under the registry lock.** `Register` calls
   `b.Name()` before taking the lock; `Lookup` and `BackendNames` call no
   backend method. A backend's `Name` may therefore call `Lookup` without
   deadlocking. `WipeAll`'s backend phase holds to it too: it
   snapshots the registered `Sweeper`s other than the default under the read
   lock, releases it, then sweeps; a backend registered after the snapshot
   waits for the next `WipeAll`
   ([architecture](architecture.md#wipeall-and-the-shutdown-sweep)).
4. **Valid names.** 1 to 64 bytes from `[a-z0-9.-]`, the first and last a
   letter or digit. The rule keeps a name safe as a configuration value, a
   file name and a metric label without escaping.
5. **Nothing panics on a malformed input.** `Register(nil)`, a typed-nil
   backend, `As` with a nil or typed-nil value, a nil target, a non-pointer
   target or a nil pointer, and `NewImportSpec` with a nil option return a
   typed error or `false`. `As` does not recover a panic from a value's own
   `As` method. Nil receivers are not part of the `Handle` contract;
   `*Memory` accepts one on every method as its own guarantee.
6. **A capability is its method set.** The type assertion is the only test of
   whether a handle or backend has a capability; there is no list to drift from
   it.
7. **A missing capability is refused, not substituted.** An operation that
   needs a capability returns a `*CapabilityError` naming the backend and the
   capability before it does anything else, and never falls back to another
   backend.

## Error semantics

| Error | From | Matches |
|---|---|---|
| `*BackendNotRegisteredError` | `Lookup` | `ErrBackendNotRegistered`; `Name` is the name asked for. |
| `*BackendExistsError` | `Register` | `ErrBackendExists`; `Name` is the taken name. |
| `ErrInvalidBackend` | `Register` | Itself. Returned bare: the name may be the problem, so it is not echoed. |
| `*CapabilityError` | `NewSealer` with `WithBackend`, `OpenIn` and `SealFrom`: operations that need a capability | `ErrCapabilityUnsupported`; `Backend` and `Capability` name what was missing. |

Texts are the sentinel's, then the detail with every name quoted
(`strconv.Quote`), so a hostile name cannot forge a log line. Match with
`errors.Is` and `errors.As`, never the text.

## Cost

`Lookup` and `BackendNames` take a read lock; `Register` a write lock. Each is
a configuration-time call, never on a borrow. `As` uses reflection once per
call. `(*Memory).Backend()` takes no lock: it returns the admitting
`*Allocator` or a zero-size default.

## Configuration and persistence

None. The registry lives for the process and is never persisted.

## Test strategy

`backend_test.go` covers the default and its name, `Memory`'s backend
(live, destroyed and nil), register and lookup, every refusal of `Register`,
the name rule at both bounds, distinct capability names, concurrent registration of distinct and of
identical names under `-race` (exactly one of the identical ones wins), `As`
on direct matches, interface targets, wrappers, typed-nil values (direct and
wrapper) and every input that would make `errors.As` panic, `NewImportSpec`
on every valid shape and every refusal, valid purpose and algorithm names,
and each error's text and sentinel. Compile-time assertions
in `backend.go` hold `*Memory` to `Handle`, `ByteAccess` and `Freezer`, and
`*Allocator` to `Backend` and `Importer`. `allocator_backend_test.go` covers
the admitting allocator as `Backend()`, `Import`, and copies of `Memory` and
`Allocator` sharing state; `wipeall_backends_test.go` covers the sweep phase.

Tests that register a backend remove it in `t.Cleanup` by editing the registry
map directly; that is the only place a name is ever unbound. There is no
integration suite: the registry touches no kernel state.

## Testing a backend

A backend author calls `backendtest.TestBackend` from a package test with a
`Config`: a factory for a fresh backend, the backend's exact capability list,
and one `HandleCase` per kind of handle it makes. Run it under `-race`. What it
checks and what it returns are in
[What it checks](architecture.md#what-it-checks). The suite's own tests run with
`make test-backendtest`, `make coverage-backendtest` (held to the coverage
floor) and `make test-backends`. Each check has a deliberately
broken fake in `backendtest/fake_test.go` that the check must catch.

## Observability

`BackendNames()` reports what is registered; log it at startup next to
`HardenProcess`'s report. A handle's `Backend().Name()` says where its material
is held.

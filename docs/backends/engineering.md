# Backends — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-31
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

This contract covers the seam and its wiring into sealing: `WithBackend`,
`OpenIn`'s `Backend` parameter, `SealFrom` and `WithRequireKeyScheduleErasure`
are contracted in [sealing](../sealing/engineering.md#exported-surface). The
conformance suite `backendtest` is contracted in
[backend-conformance](../backend-conformance/engineering.md).

## Interface signatures

Exact signatures; the godoc in [backend.go](../../backend.go) is the full
contract of each method.

```go
// Core.
type Handle interface {
	Size() int        // bytes of material; 0 once destroyed
	IsAlive() bool    // still holds its material
	Destroy() error   // idempotent, waits out borrows, typed errors only
	Backend() Backend // never nil, also once destroyed
}

type Backend interface {
	Name() string // [a-z0-9]([a-z0-9.-]*[a-z0-9])?, 1 to 64 bytes, stable
}

// Handle capabilities.
type ByteAccess interface {
	Handle
	WithBytes(fn func([]byte) error) error
	EqualTo(other []byte) (bool, error)
}

type Freezer interface {
	Handle
	Freeze() error
}

type Deriver interface {
	Handle
	Derive(ctx context.Context, info []byte, n int) (Handle, error)
}

type AEAD interface {
	Handle
	NonceSize() int // constant of the algorithm, valid after Destroy
	Overhead() int  // constant of the algorithm, valid after Destroy
	Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error)
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// Handle or backend capability.
type Attester interface {
	Attest(ctx context.Context, nonce []byte) (Evidence, error)
}

type Evidence struct {
	Format string // e.g. "tdx-quote", "sev-snp-report"
	Data   []byte
}

// Backend capabilities.
type Importer interface {
	Backend
	Import(ctx context.Context, material []byte, opts ...ImportOption) (Handle, error)
}

type Sweeper interface {
	Backend
	Sweep(ctx context.Context) (held int, err error)
}

type Confiner interface {
	Backend
	ConfinesProcess() bool // this whole process runs inside the backend's boundary
}

type Prober interface {
	Backend
	Rank() int                       // higher is more secure; locked memory is 0
	Probe(ctx context.Context) error // nil when usable on this host
}

// Import intent.
type Purpose string   // PurposeMaterial "material", PurposeWrappingKey "wrapping-key", PurposeDataKey "data-key"
type Algorithm string // AlgorithmAES256GCM "aes-256-gcm"; a backend module may name its own

type ImportSpec struct {
	Purpose   Purpose
	Algorithm Algorithm
}

type ImportOption func(*ImportSpec)

func WithPurpose(p Purpose) ImportOption
func WithAlgorithm(a Algorithm) ImportOption
func NewImportSpec(opts ...ImportOption) (ImportSpec, error)

// Registry.
const LockedMemoryBackendName = "locked-memory"

func DefaultBackend() Backend
func Register(b Backend) error
func Lookup(name string) (Backend, error)
func BackendNames() []string
func As(v, target any) bool

// Errors.
var ErrBackendNotRegistered, ErrBackendExists, ErrInvalidBackend, ErrCapabilityUnsupported error
var ErrInvalidImport, ErrInvalidNonce, ErrAEADAuthentication, ErrCleanupFailed error

type BackendNotRegisteredError struct{ Name string }
type BackendExistsError struct{ Name string }
type CapabilityError struct {
	Backend    string
	Capability Capability
}
type CleanupError struct {
	Failure error
	Causes  []error
}

type Capability string // "bytes", "freeze", "sign", "decrypt", "aead", "derive", "attest", "import", "sweep", "confine", "probe"
```

The memory enclave's internal type, `*lockedRegion`, satisfies `Handle`,
`ByteAccess` and `Freezer`, asserted at compile time; callers hold the
`ByteAccess` and reach `Freezer` with `As`. Every handle's dynamic type is a pointer to shared state, and handle
structs carry a `noCopy` field so `go vet`'s copylocks check reports a
dereferenced copy ([architecture](architecture.md#lifetime-and-ownership)).

## Exported surface

| Identifier | Contract |
|---|---|
| `Handle` | The core of every backend's enclave: `Size`, `IsAlive`, `Destroy`, `Backend`. The dynamic type is a pointer; every method, the capabilities' included, is concurrency-safe and never panics on a live or destroyed handle. After `Destroy` every capability method that returns an error returns `ErrEnclaveDestroyed`; one without an error result (`AEAD`'s `NonceSize` and `Overhead`, `Public()`) keeps reporting its non-secret constant. A nil receiver is outside the contract. |
| `Backend` | The core of every backend: `Name`, valid and stable for the backend's life. A name is a registry and configuration label, not an instance identity. |
| `ByteAccess` | Handle capability: `WithBytes`, `EqualTo`, with the contract `NewMemory` documents for a memory enclave. |
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
| `Prober` | Backend capability: `Rank()`, fixed for the backend's life and without blocking, reports how secure the backend is (higher is more; locked memory reports 0), and `Probe(ctx)` returns nil when the backend is usable on this host or its own typed error. `Detect` compares them ([backend detection](../backend-detection/engineering.md)). |
| `Capability`, `CapabilityBytes` … `CapabilityConfine`, `CapabilityProbe` | Names a capability in a `CapabilityError`; one constant per interface above and per standard opaque shape (`crypto.Signer`, `crypto.Decrypter`). |
| `LockedMemoryBackendName` | `"locked-memory"`: the default backend's name, always registered. |
| `DefaultBackend() Backend` | The locked-memory backend; a `Prober` of rank 0 whose `Probe` returns nil. |
| `Register(b Backend) error` | Adds `b` under `b.Name()`. Never rebinds a name. |
| `Lookup(name string) (Backend, error)` | The backend registered under `name`. |
| `BackendNames() []string` | Every registered name, sorted, the default included. |
| `As(v, target any) bool` | Sets `*target` to `v` when `v`'s dynamic type is assignable to it, else defers to `v`'s `As(any) bool` method. A nil or typed-nil `v` or a bad target returns `false` without panicking; a panic from `v`'s own `As` is not recovered. |
| `Handle.Backend()` of a memory enclave | The `Allocator` that admitted the enclave, else `DefaultBackend()`; unchanged by `Destroy`. |
| `Allocator` as `Backend`, `Importer` and `Prober` | Name `"locked-memory"`, ranked and probed as the default; `Import` is an admitted `New` that resolves `NewImportSpec` and refuses an `AlgorithmAES256GCM` key that is not 32 bytes with `ErrInvalidImport` ([budget](../locked-memory-budget/engineering.md)). Never registered. |
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
   for an injected, unregistered backend or a budgeted `Allocator`. A
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
   the memory enclave's internal `*lockedRegion` accepts one on every method,
   a guarantee inside the package only.
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
call. A memory enclave's `Backend()` takes no lock: it returns the admitting
`Allocator` or a zero-size default.

## Configuration and persistence

None. The registry lives for the process and is never persisted.

## Test strategy

`backend_test.go` covers the default and its name, a memory enclave's backend
(live, destroyed and nil), register and lookup, every refusal of `Register`,
the name rule at both bounds, distinct capability names, concurrent registration of distinct and of
identical names under `-race` (exactly one of the identical ones wins), `As`
on direct matches, interface targets, wrappers, typed-nil values (direct and
wrapper) and every input that would make `errors.As` panic, `NewImportSpec`
on every valid shape and every refusal, valid purpose and algorithm names,
and each error's text and sentinel. Compile-time assertions
in `backend.go` hold `*lockedRegion` to `Handle`, `ByteAccess` and `Freezer`, the
default to `Prober`, and `Allocator` to `Backend`, `Importer` and `Prober`. `allocator_backend_test.go` covers
the admitting allocator as `Backend()`, `Import`, and copies of a memory enclave
and of an `Allocator` sharing state; `enclave_test.go` covers `As` reaching
`Freezer` through a constructor's `ByteAccess` and refusing a foreign one; `wipeall_backends_test.go` covers the sweep phase.

Tests that register a backend remove it in `t.Cleanup` by editing the registry
map directly; that is the only place a name is ever unbound.
`make integration-test-backends` runs the `TestBackends_` tests in
`test/integration/enclave`: registration, lookup and `As` through the public
API, `NewImportSpec`, and the `Allocator` as a backend that names itself,
imports into its budget and refuses an import it cannot honour.

## Testing a backend

A backend author calls `backendtest.TestBackend` from a package test. What it
checks, what it returns and how its own tests run are in
[backend-conformance](../backend-conformance/engineering.md).

## arm-trustzone

The nested module `backends/armtrustzone` requires the released root
(`v0.11.0-alpha`) and `golang.org/x/sys`, with no `replace` or `go.work`; the
root module never requires it ([design](arm-trustzone-design.md), decision 1).

| Identifier | Contract |
|---|---|
| `Name` | `"arm-trustzone"`, the `Backend` and `Connector` name. |
| `Connect(endpoint string) (*Backend, error)` | Opens the TEE device, checks `TEE_IOC_VERSION` reports a GlobalPlatform TEE, opens a public-login session to TA `23751b49-3a76-4e49-b63c-e5853742fa1f` and probes it; closes everything on failure. Off Linux, `*PlatformError` before any I/O. |
| `Backend.Rank()`, `Backend.Probe(ctx)` | `Prober`: rank 2, above secretmem; `Probe` invokes GET_INFO (0x1) and accepts only interface version 1 with flags 0. |
| `Backend.Random(ctx, n) (enclave.Handle, error)` | A `ByteAccess` memory enclave of `n` bytes filled by GET_RANDOM (0x2) in chunks of at most 4096 bytes. `n < 1` is a `*SizeError` before the TA is called. A cancelled `ctx` issues `TEE_IOC_CANCEL` and returns `ctx.Err()`; on any failure the handle is destroyed. |
| `Backend.Close()` | Closes the session and the device; idempotent; afterwards every call returns `ErrBackendClosed`. |
| `Connector` | A registrable `Backend` whose `Connect(endpoint) (enclave.Backend, error)` is `Connect`. |
| `OriginAPI` … `OriginTrustedApp` | The GP return origins a `SessionError` or `CommandError` reports. |

Shared memory follows the [trust boundary](arm-trustzone-design.md#trust-boundary):
with the driver's `TEE_GEN_CAP_REG_MEM` the handle's own pages are
registered (`TEE_IOC_SHM_REGISTER`) and the TA writes into them; otherwise
driver memory (`TEE_IOC_SHM_ALLOC`, `mmap`) is copied from per chunk and
zeroed after each copy and before `munmap`, on every path. The ioctl structs
and numbers are the pinned [`tee.h`](../reference/linux-uapi-tee.h); the TA
UUID's byte order is [RFC 9562](../reference/rfc9562.txt).

| Error | Matches |
|---|---|
| `*PlatformError{GOOS}` | `ErrUnsupportedPlatform` |
| `*DeviceError{Endpoint; Op; Cause}` | `ErrDeviceUnavailable`, and its cause (`fs.ErrNotExist`, `ErrNotGlobalPlatform`, an errno). `Op` is `open`, `version`, `open-session`, `invoke`, `shm-alloc`, `mmap`, `close-session` or `close`. |
| `*SessionError{Code; Origin}` | `ErrSessionRefused` |
| `*CommandError{Command; Code; Origin}` | `ErrCommandFailed` |
| `*InterfaceError{Version; Flags}` | `ErrInterfaceUnsupported` |
| `*SizeError{N}` | `ErrRandomSize` |
| `*ShortRandomError{Want; Got}` | `ErrShortRandom` |
| `*UUIDError{Text}` | `ErrInvalidUUID` |
| `ErrBackendClosed` | Itself. |

Unit tests cover only pure functions: the struct layouts, offsets and ioctl
numbers against `tee.h`, the `TEEC_UUID` byte order, the chunk plan, the
`n < 1` refusal, GET_INFO's acceptance, and `Connect` on a missing device and
off Linux. No mock or simulator stands in for the TEE (owner queue 41).
`conformance_optee_test.go` (tag `optee`) registers the backend and runs
`backendtest.TestBackend` with the probe and an `rng` handle case against
`GO_ENCLAVE_OPTEE_ENDPOINT`; the harness running it in the OP-TEE guest is
slice 3. `make lint-go`, `tidy-check`, `govulncheck`, `test` and
`cross-build` run in the module (`BACKEND_MODULES`); coverage does not.

## Observability

`BackendNames()` reports what is registered; log it at startup next to
`HardenProcess`'s report. A handle's `Backend().Name()` says where its material
is held.

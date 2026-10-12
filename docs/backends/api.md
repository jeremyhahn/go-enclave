# Backends — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-11
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; other transports are not
applicable (see [locked-memory/api.md](../locked-memory/api.md#transports)).
A backend is code linked into the process; registering one remotely would let
a peer choose where the process keeps its keys.

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Register a backend | `enclave.Register(b) error` | N/A |
| Select a backend by name | `enclave.Lookup(name) (enclave.Backend, error)` | N/A |
| List registered backends | `enclave.BackendNames() []string` | N/A |
| The default backend | `enclave.DefaultBackend()`, named `enclave.LockedMemoryBackendName` | N/A |
| Use a handle | `h.Size()`, `h.IsAlive()`, `h.Destroy() error`, `h.Backend()` | N/A |
| Where a handle's material is held | `h.Backend().Name()` | N/A |
| Hold a sealer's keys in a backend | `enclave.WithBackend(b)`: see [sealing/api.md](../sealing/api.md) | N/A |
| Open sealed material into a backend | `(*Sealed).OpenIn(ctx, b) (Handle, error)`: see [sealing/api.md](../sealing/api.md) | N/A |
| Test a handle for a capability | `ba, ok := h.(enclave.ByteAccess)` (likewise `Freezer`, `Deriver`, `AEAD`, `crypto.Signer`, `crypto.Decrypter`) | N/A |
| Test a backend for a capability | `imp, ok := b.(enclave.Importer)` (likewise `Sweeper`, `Confiner`) | N/A |
| Test for attestation, on either | `a, ok := h.(enclave.Attester)` (key evidence) or `a, ok := b.(enclave.Attester)` (platform evidence) | N/A |
| Import with a purpose | `imp.Import(ctx, material, enclave.WithPurpose(p), enclave.WithAlgorithm(a))`; a backend resolves the set with `enclave.NewImportSpec(opts...)` | N/A |
| Reach a native interface | `enclave.As(v, &target) bool` | N/A |
| Detect a missing capability | `var ce *enclave.CapabilityError; errors.As(err, &ce)` → `ce.Backend`, `ce.Capability` | N/A |
| Check a backend | `backendtest.TestBackend`: see [backend-conformance/api.md](../backend-conformance/api.md) | N/A |

Schemas and error mapping: [engineering.md](engineering.md#error-semantics).

## Exported symbols

Every exported symbol of the seam. Contracts are in
[engineering.md](engineering.md#exported-surface), exact signatures in
[engineering.md](engineering.md#interface-signatures).

### Interfaces

| Symbol | On | Methods |
|---|---|---|
| `Handle` | every enclave | `Size() int`, `IsAlive() bool`, `Destroy() error`, `Backend() Backend` |
| `Backend` | every backend | `Name() string` |
| `ByteAccess` | handle | `WithBytes(fn func([]byte) error) error`, `EqualTo(other []byte) (bool, error)` |
| `Freezer` | handle | `Freeze() error` |
| `Deriver` | handle | `Derive(ctx, info []byte, n int) (Handle, error)` |
| `AEAD` | handle | `NonceSize() int`, `Overhead() int`, `Seal(dst, nonce, plaintext, additionalData []byte) ([]byte, error)`, `Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)` |
| `Attester` | handle or backend | `Attest(ctx, nonce []byte) (Evidence, error)` |
| `Importer` | backend | `Import(ctx, material []byte, opts ...ImportOption) (Handle, error)` |
| `Sweeper` | backend | `Sweep(ctx) (held int, err error)` |
| `Confiner` | backend | `ConfinesProcess() bool` |

### Types and constants

| Symbol | Kind | Summary |
|---|---|---|
| `Evidence{Format string; Data []byte}` | struct | What `Attest` returns; never parsed by this package. |
| `ImportSpec{Purpose; Algorithm}` | struct | An import's resolved options. |
| `ImportOption` | func type | `func(*ImportSpec)`; built by `WithPurpose` and `WithAlgorithm`. |
| `Purpose` | string type | What imported material is for. |
| `PurposeMaterial` (`"material"`), `PurposeWrappingKey` (`"wrapping-key"`), `PurposeDataKey` (`"data-key"`) | constants | The three purposes. |
| `Algorithm` | string type | The algorithm an imported key is for. |
| `AlgorithmAES256GCM` (`"aes-256-gcm"`) | constant | The algorithm this module names. |
| `Capability` | string type | Names a capability in a `CapabilityError`. |
| `CapabilityBytes` (`"bytes"`), `CapabilityFreeze` (`"freeze"`), `CapabilitySign` (`"sign"`), `CapabilityDecrypt` (`"decrypt"`), `CapabilityAEAD` (`"aead"`), `CapabilityDerive` (`"derive"`), `CapabilityAttest` (`"attest"`), `CapabilityImport` (`"import"`), `CapabilitySweep` (`"sweep"`), `CapabilityConfine` (`"confine"`) | constants | One per capability: `ByteAccess`, `Freezer`, `crypto.Signer`, `crypto.Decrypter`, `AEAD`, `Deriver`, `Attester`, `Importer`, `Sweeper`, `Confiner`. |
| `LockedMemoryBackendName` (`"locked-memory"`) | constant | The default backend's name. |

### Functions

| Symbol | Summary |
|---|---|
| `WithPurpose(p Purpose) ImportOption`, `WithAlgorithm(a Algorithm) ImportOption` | Set the purpose and the algorithm of an import. |
| `NewImportSpec(opts ...ImportOption) (ImportSpec, error)` | Resolves the options; `ErrInvalidImport` on a refusal. |
| `DefaultBackend() Backend` | The locked-memory backend. |
| `Register(b Backend) error` | Adds `b` under `b.Name()`. |
| `Lookup(name string) (Backend, error)` | The backend registered under `name`. |
| `BackendNames() []string` | Every registered name, sorted. |
| `As(v, target any) bool` | Reaches a native interface through a wrapper. |
| `(*Memory).Backend() Backend`, `(*Allocator).Name() string`, `(*Allocator).Import(...)` | The locked-memory backend's side of the seam. |

### Errors

| Sentinel | Typed error | Returned when |
|---|---|---|
| `ErrBackendNotRegistered` | `*BackendNotRegisteredError{Name}` | `Lookup` found no backend under `Name`. |
| `ErrBackendExists` | `*BackendExistsError{Name}` | `Register` found `Name` taken. |
| `ErrInvalidBackend` | none | A nil or typed-nil backend, or an invalid name. |
| `ErrCapabilityUnsupported` | `*CapabilityError{Backend, Capability}` | An operation needs a capability the handle or backend lacks. |
| `ErrInvalidImport` | none | `NewImportSpec` refused the options, or an `Importer` refused the material's length. |
| `ErrInvalidNonce` | none | An `AEAD` got a nonce that is not `NonceSize` bytes. |
| `ErrAEADAuthentication` | none | An `AEAD`'s `Open` could not authenticate. |
| `ErrCleanupFailed` | `*CleanupError{Failure, Causes}` | A handle no longer needed refused its `Destroy`, or cleanup failed alongside another failure. |

The typed errors are returned as pointers, so `errors.As` needs a pointer
target: `var ce *enclave.CapabilityError; errors.As(err, &ce)`.

`ErrEnclaveDestroyed` is the lifecycle sentinel for every backend's handles
([locked-memory/api.md](../locked-memory/api.md)).

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

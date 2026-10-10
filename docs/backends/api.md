# Backends — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-10
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

Schemas and error mapping: [engineering.md](engineering.md#error-semantics).

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability. The seam is new in v0.9.0-alpha. Its wiring and the renames
[architecture.md](architecture.md#renames) decides land in v0.9.0-alpha
too, as a clean break with no deprecated aliases.

# Sealing and the provider seam — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-14
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; other transports are not
applicable (see [memory-enclave/api.md](../memory-enclave/api.md#transports)). A
provider that talks to a device over a network (a cloud KMS) owns that
transport itself, behind the `KeyProtector`/`RootUnsealer` interfaces.

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Seal under the process sealer | `enclave.NewSealed(ctx, data)`, or from an enclave `enclave.NewSealedFrom(ctx, src)` | N/A |
| Configure a sealer | `enclave.NewSealer(enclave.WithKeyProtector(kp))` or `enclave.NewSealer(enclave.WithRootUnsealer(ru), enclave.WithKEKRotationLimit(n))`; `enclave.WithBackend(b)` for where its keys live, `enclave.WithRequireKeyScheduleErasure()` for strict mode | N/A |
| Install the process sealer | `enclave.SetSealer(s)` | N/A |
| Seal under an explicit sealer | `Sealer.Seal(ctx, data)`, `Sealer.SealFrom(ctx, src)`, each returning the `Sealed` interface | N/A |
| Open (locked memory / another backend) | `Sealed.Open(ctx)` (a `ByteAccess`), `Sealed.OpenIn(ctx, b)` (a `Handle`; into `NewSecretMemory` it decrypts straight into secretmem pages) | N/A |
| Read a sealer's mode | `Sealer.Mode()` | N/A |
| Probe openability | `Sealed.Openable()`, `Sealed.IsAlive()` | N/A |
| Release ciphertext | `Sealed.Destroy() error` | N/A |
| End a sealer and release its keys | `Sealer.Destroy() error` (what it releases per mode: [engineering.md](engineering.md#exported-surface)) | N/A |
| Release the software provider's root | `SoftwareProvider.Destroy() error` | N/A |
| Implement a provider | `KeyProtector`, `RootUnsealer`, optional `HealthReporter`, `RootKeyBytes` | N/A |
| Software provider | `enclave.NewSoftwareProvider()` | N/A |
| Check key-schedule erasure | `enclave.KeyScheduleErasure()` | N/A |

Schemas and error mapping: [engineering.md](engineering.md). No permission
scope; no pagination.

## Exported symbols

Every exported symbol of the feature. The contract of each is in
[engineering.md](engineering.md#exported-surface); this table names it.

### Types, constants and constructors

| Symbol | Kind | Notes |
|---|---|---|
| `Mode` | `uint8` type | How a `Sealer` uses its provider. `String()` names it (`ModeRootKey`, `ModePerOperation`, else `Mode(n)`). |
| `ModeRootKey` | `Mode` constant | The zero value: unseal a root once, run an in-memory KEK hierarchy. Selected by `WithRootUnsealer`, and by no provider option. |
| `ModePerOperation` | `Mode` constant | Protect and unprotect each value's DEK through the provider on every seal and open. Selected by `WithKeyProtector`. |
| `SealerOption` | `func(*sealerConfig)` type | An option of `NewSealer`. A nil option is `ErrInvalidSealerOption`. |
| `Sealer` | interface | Seals values and opens them. Returned by `NewSealer`; the implementation is internal, and `SetSealer` refuses any other with `ErrSealerNotConstructed`. |
| `Sealed` | interface | An envelope of ciphertext on the heap, returned by `NewSealed`, `NewSealedFrom`, `Seal` and `SealFrom`; the implementation is internal. Under `%v`, `%s` and `%#v` it prints a redacted form, `Sealed(sealed)` or `Sealed(destroyed)`, never the ciphertext. |
| `NewSealer`, `WithKeyProtector`, `WithRootUnsealer`, `WithKEKRotationLimit`, `WithBackend`, `WithRequireKeyScheduleErasure` | functions | Construction and options. |
| `SetSealer`, `NewSealed`, `NewSealedFrom` | functions | The process sealer: install it, seal under it. |
| `KeyScheduleErasure` | function | Whether this build erases AES key schedules. |
| `KeyProtector`, `RootUnsealer`, `HealthReporter`, `RootKeyBytes` | interfaces, constant | The provider seam. |
| `SoftwareProvider`, `NewSoftwareProvider` | interface, function | The shipped provider: `KeyProtector`, `RootUnsealer` and `HealthReporter` plus `Destroy`. `NewSoftwareProvider` returns the interface; the implementation is internal. |

### Methods

| Method | Notes |
|---|---|
| `Sealer.Seal`, `SealFrom`, `Mode`, `Destroy` | Seal, seal from an enclave, read the mode, end the sealer. |
| `Sealed.Open`, `OpenIn`, `Openable`, `IsAlive`, `Destroy` | Open into locked memory or another backend, probe, release. |
| `(Mode).String` | See above. |

### Errors

Sentinels: `ErrSealFailed`, `ErrOpenFailed`, `ErrSealedAuthentication`,
`ErrPlaintextEscaped`, `ErrMaterialTooLarge`, `ErrSealerWiped`,
`ErrOpenabilityUnknown`, `ErrInvalidProvider`, `ErrSealerExhausted`,
`ErrInvalidRotationLimit`, `ErrSealerInstalled`, `ErrNilSealer`,
`ErrSealerDestroyed`, `ErrSealerNotConstructed`, `ErrInvalidSealerOption`,
`ErrSealSourceReadOnly`, `ErrKeyScheduleExposed`, `ErrProviderMessageLimit`,
`ErrProviderNotConstructed`. Types: `*SealError`, `*OpenError`,
`*SealerWipedError` (each with `Cause`) and `*KeyScheduleExposedError` (`Name`).
Match a sentinel with `errors.Is` and read a type with `errors.As`; meaning,
origin and handling of each: [engineering.md](engineering.md#error-semantics).

The same paths also return errors defined by other features, documented where
they belong, with their meaning on a sealing path in
[engineering.md](engineering.md#error-semantics): `ErrEmptyEnclave`,
`ErrEnclaveDestroyed`, `ErrLockedMemoryUnavailable`, `ErrBudgetExhausted`, `ErrInvalidBackend`, `ErrCleanupFailed`
(`*CleanupError`) and `*CapabilityError` (the [feature index](../README.md)
lists those features).

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

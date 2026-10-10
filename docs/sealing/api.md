# Sealing and the provider seam — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-07
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; other transports are not
applicable (see [locked-memory/api.md](../locked-memory/api.md#transports)). A
provider that talks to a device over a network (a cloud KMS) owns that
transport itself, behind the `KeyProtector`/`RootUnsealer` interfaces.

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Seal under the process sealer | `enclave.NewSealed(ctx, data)`, or from an enclave `enclave.NewSealedFrom(ctx, src)` | N/A |
| Configure a sealer | `enclave.NewSealer(enclave.WithKeyProtector(kp))` or `enclave.NewSealer(enclave.WithRootUnsealer(ru), enclave.WithKEKRotationLimit(n))`; `enclave.WithBackend(b)` for where its keys live, `enclave.WithRequireKeyScheduleErasure()` for strict mode | N/A |
| Install the process sealer | `enclave.SetSealer(s)` | N/A |
| Seal under an explicit sealer | `(*Sealer).Seal(ctx, data)`, `(*Sealer).SealFrom(ctx, src)` | N/A |
| Open (locked memory / another backend) | `(*Sealed).Open(ctx)`, `(*Sealed).OpenIn(ctx, b)` | N/A |
| Probe openability | `(*Sealed).Openable()` | N/A |
| Release ciphertext | `(*Sealed).Destroy() error` | N/A |
| Release a sealer's keys | `(*Sealer).Destroy() error` | N/A |
| Release the software provider's root | `(*SoftwareProvider).Destroy() error` | N/A |
| Implement a provider | `KeyProtector`, `RootUnsealer`, optional `HealthReporter`, `RootKeyBytes` | N/A |
| Software provider | `enclave.NewSoftwareProvider()` | N/A |
| Check key-schedule erasure | `enclave.KeyScheduleErasure()` | N/A |

Schemas and error mapping: [engineering.md](engineering.md). No permission
scope; no pagination.

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

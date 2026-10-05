# Sealing and the provider seam — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-04
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; other transports are not
applicable (see [locked-memory/api.md](../locked-memory/api.md#transports)). A
provider that talks to a device over a network (a cloud KMS) owns that
transport itself, behind the `KeyProtector`/`RootUnsealer` interfaces.

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Seal under the process sealer | `enclave.NewSealed(ctx, data)` | N/A |
| Configure a sealer | `enclave.NewSealer(enclave.WithKeyProtector(kp))` or `enclave.NewSealer(enclave.WithRootUnsealer(ru), enclave.WithKEKRotationLimit(n))` | N/A |
| Install the process sealer | `enclave.SetSealer(s)` | N/A |
| Seal under an explicit sealer | `(*Sealer).Seal(ctx, data)` | N/A |
| Open (unbudgeted / budgeted) | `(*SealedEnclave).Open(ctx)`, `(*SealedEnclave).OpenWith(ctx, a)` | N/A |
| Probe openability | `(*SealedEnclave).Openable()` | N/A |
| Release ciphertext | `(*SealedEnclave).Destroy() error` | N/A |
| Release a sealer's keys | `(*Sealer).Destroy() error` | N/A |
| Release the software provider's root | `(*SoftwareProvider).Destroy() error` | N/A |
| Implement a provider | `KeyProtector`, `RootUnsealer`, optional `HealthReporter`, `RootKeyBytes` | N/A |
| Software provider | `enclave.NewSoftwareProvider()` | N/A |
| Check key-schedule erasure | `enclave.KeyScheduleErasure()` | N/A |

Schemas and error mapping: [engineering.md](engineering.md). No permission
scope; no pagination.

## Versioning

v0.7 is BREAKING for this capability: every call that can reach a provider,
and every provider method, takes a `context.Context` first, and provider
infrastructure failures on open are joined under the new `ErrOpenFailed`. See
[user.md](user.md#migrating-from-v06).

# Backend detection — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-14
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; other transports are not
applicable (see [memory-enclave/api.md](../memory-enclave/api.md#transports)).

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Select the most secure usable backend | `enclave.Detect(ctx)`, returning the `Backend` and one `ProbeResult` per registered backend | N/A |
| Report a backend's rank | `Prober.Rank() int` | N/A |
| Probe whether this host can run a backend | `Prober.Probe(ctx) error` | N/A |
| Check a backend's rank and probe | `backendtest.TestBackend` with `enclave.CapabilityProbe` claimed ([backend conformance](../backend-conformance/api.md)) | N/A |

Schemas and error mapping: [engineering.md](engineering.md). No permission
scope; no pagination.

## Exported symbols

Every exported symbol of the feature. The contract of each is in
[engineering.md](engineering.md#exported-surface); this table names it.

| Symbol | Kind | Notes |
|---|---|---|
| `Detect` | function | `Detect(ctx context.Context) (Backend, []ProbeResult)`. Never fails: it falls back to `DefaultBackend()`. |
| `ProbeResult` | struct | `Backend string` (the registered name), `Rank int`, `Err error` (nil when usable, else why it was passed over). |
| `Prober` | interface | `Backend` plus `Rank() int` and `Probe(ctx context.Context) error`; an optional backend capability, defined with the [backends](../backends/api.md) seam. |
| `CapabilityProbe` | `Capability` constant | `"probe"`: the name a `*CapabilityError` gives a backend that is no `Prober`. |

The locked-memory default and every `Allocator` are `Prober`s of rank 0 whose
`Probe` returns nil.

### Errors

Sentinel: `ErrBackendUnavailable`. Type: `*ProbeError` (`Backend`, `Cause`),
matching `ErrBackendUnavailable` and unwrapping to `Cause`. A backend that is
no `Prober` is passed over with a `*CapabilityError` for `CapabilityProbe`
([backends](../backends/engineering.md#error-semantics)). Match a sentinel with
`errors.Is` and read a type with `errors.As`; meaning and handling:
[engineering.md](engineering.md#error-semantics).

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

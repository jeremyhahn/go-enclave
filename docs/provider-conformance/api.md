# Provider conformance — API

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-11
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Transports

The embedded Go call is the only transport; the suite runs inside the provider
author's test binary. Other transports are not applicable (see
[locked-memory/api.md](../locked-memory/api.md#transports)).

| Capability | Embedded Go call | REST / gRPC / QUIC / MCP / Unix socket |
|---|---|---|
| Run the conformance suite | `providertest.TestProvider(ctx, providertest.Config{...})` | N/A |
| Distinguish harness error / aborted run / provider defect | `errors.Is(err, providertest.ErrInvalidConfig)`, `errors.Is(err, providertest.ErrAborted)`, `errors.Is(err, providertest.ErrNotMeasured)`, `var pe *providertest.PropertyError; errors.As(err, &pe)` | N/A |

Schemas and error mapping: [engineering.md](engineering.md).

## Exported symbols

Package `providertest`. Behavior of each: [engineering.md](engineering.md).

### Function and configuration

| Symbol | Notes |
|---|---|
| `TestProvider(ctx context.Context, cfg Config) error` | Runs the suite against `cfg.New`'s providers. Returns `nil`, or an error described under [Errors](#errors). |
| `Config` | The run's input. Fields below. |

| `Config` field | Type | Meaning |
|---|---|---|
| `New` | `func() (any, error)` | Required. Returns a fresh provider (a `KeyProtector`, a `RootUnsealer`, or both); called once per check, twice by the mode-pairing check. A nil or typed-nil result is a finding. Instances need not be independent. |
| `Modes` | `[]enclave.Mode` | Required, non-empty, valid modes only. The modes the provider claims; a claimed mode must be implemented and accepted by `enclave.NewSealer`, an unclaimed one must not be implemented. |
| `SkipResidueSweep` | `string` | A non-empty reason skips the process-memory residue sweep and is echoed to `Logf`. Left empty, a sweep that cannot run is `ErrNotMeasured`. |
| `SingleUseRoot` | `string` | A non-empty reason: `UnsealRoot` succeeds once per instance. Relaxes the two checks that need a second call; root-destination retention is then unmeasured. Echoed to `Logf`. |
| `PublicKey` | `bool` | `Protect` needs no secret (an RSA-OAEP, ECIES or HPKE wrap). Without `Forge`, forgery is unmeasured (`ErrNotMeasured`) unless `SkipForgery` accepts that. Requires `ModePerOperation` in `Modes`. |
| `Forge` | `func(p enclave.KeyProtector, key []byte) ([]byte, error)` | Builds, from the provider's public material alone, a blob wrapping `key`; `Unprotect` must refuse it with `enclave.ErrSealedAuthentication`. Runs whether or not `PublicKey` is set. Requires `ModePerOperation` in `Modes`. |
| `SkipForgery` | `string` | A non-empty reason skips the forged-blob check, echoed to `Logf`. |
| `Logf` | `func(format string, args ...any)` | Receives what was measured and what was skipped; pass `t.Logf`. Nil discards the notes. |

### Errors

| Sentinel | Type | Fields | Returned when |
|---|---|---|---|
| `ErrInvalidConfig` | `*ConfigError` | `Field`, `Reason` | The `Config` cannot be run at all (nil `New`, empty or invalid `Modes`, `PublicKey` or `Forge` without `ModePerOperation`). No provider was tested. |
| `ErrAborted` | `*AbortedError` | `Cause` (the run context's error; also reached by `Unwrap`) | `ctx` ended before the run finished. The run is incomplete, not a pass. |
| `ErrNotMeasured` | `*NotMeasuredError` | `Property`, `Reason` | A property could not be measured on this host and the `Config` did not accept that. |
| | `*PropertyError` | `Property`, `Detail` | One assertion the provider failed. Several may share a `Property`. |
| | `*FindingsError` | `Findings []error` | Wraps a run's findings: every `*PropertyError`, `*NotMeasuredError` and `*AbortedError`, in the order found. `errors.Is` and `errors.As` reach each through `Unwrap() []error`. |

A rejected `Config` returns a bare `*ConfigError`. Any other failing run returns
one `*FindingsError`; a run with no finding returns `nil`.

### Reference provider

Package `enclave`. `SoftwareProvider` is the one provider go-enclave ships, the
default of `NewSealer`, and the provider `providertest`'s own tests hold to the
suite. What it guarantees and its key derivation are in
[sealing/engineering.md](../sealing/engineering.md#exported-surface); its
errors are in [sealing/api.md](../sealing/api.md#errors).

| Symbol | Notes |
|---|---|
| `SoftwareProvider` | Implements `KeyProtector`, `RootUnsealer` and `HealthReporter`; safe for concurrent use. The zero value is not usable: every method but `Destroy` returns `ErrProviderNotConstructed`. A copy shares the original's root and lock. |
| `NewSoftwareProvider() *SoftwareProvider` | Returns a provider with no root yet; the root is generated into locked memory at first use. |
| `(*SoftwareProvider).Protect(ctx context.Context, key []byte) ([]byte, error)` | `KeyProtector`: wraps `key` under a key derived from the root, never the root itself. |
| `(*SoftwareProvider).Unprotect(ctx context.Context, blob, key []byte) error` | `KeyProtector`: recovers a blob its own `Protect` produced into `key`; refuses anything else with `ErrSealedAuthentication`. |
| `(*SoftwareProvider).UnsealRoot(ctx context.Context, dst []byte) error` | `RootUnsealer`: copies the root into `dst`, which must be `RootKeyBytes` long (`ErrInvalidSize`). |
| `(*SoftwareProvider).Health() error` | `HealthReporter`: `nil`, `ErrSealerWiped` after a shutdown sweep took the root, or `ErrSealerDestroyed` after `Destroy`. Never generates a root. |
| `(*SoftwareProvider).Destroy() error` | Releases the root and the Protect key; later calls, on it or a copy, return `ErrSealerDestroyed`. Idempotent, safe on a nil or zero provider. |

## Versioning

Pre-1.0: see [Upgrading](../README.md#upgrading) for every breaking change to
this capability.

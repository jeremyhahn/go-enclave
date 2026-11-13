# Backend detection — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-14
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

`enclave.Detect` picks the most secure [backend](../backends/user.md) this
host can run from those `main` registered. It falls back to locked memory when
no other is usable, and it says why it passed each other backend over
([architecture](architecture.md)).

## Prerequisites

None for locked memory: it is always registered and always usable. A hardware
backend must be registered first, and it takes part only if it is an
`enclave.Prober` (it reports a rank and probes the host). Its module documents
whether it is.

## Detect the backend at startup

Register what you link in, then call `Detect` once from `main`. Nothing
detects on import.

```go
for _, b := range []enclave.Backend{teeBackend, seBackend} { // hardware backend modules
	if err := enclave.Register(b); err != nil {
		return err
	}
}

backend, results := enclave.Detect(ctx)
for _, r := range results {
	slog.Info("enclave backend", "name", r.Backend, "rank", r.Rank, "unusable", r.Err)
}
slog.Info("enclave backend selected", "name", backend.Name())

sealer, err := enclave.NewSealer(enclave.WithBackend(backend), enclave.WithKeyProtector(kp))
```

`ctx` reaches every backend's probe, so bound it with a deadline when a probe
may wait on a device. With only locked memory registered, `Detect` returns
`enclave.DefaultBackend()`.

## Require a hardware backend

`Detect` never fails: locked memory is a valid result. If a deployment must
not run without hardware, check the selection and stop:

```go
if backend.Name() == enclave.LockedMemoryBackendName {
	return errNoHardwareEnclave // your own typed error
}
```

## Make a backend you wrote detectable

Implement `Rank() int` and `Probe(ctx context.Context) error` beside `Name`.
Rank above 0 when the backend is more secure than locked memory. Probe returns
nil when this host can run it and your own typed error when it cannot, such as
a missing device or a denied permission. Claim `enclave.CapabilityProbe` in the
[conformance suite](../backend-conformance/user.md), which checks that both are
stable and safe to call concurrently.

## Troubleshooting

| In a `ProbeResult.Err` | Cause and fix |
|---|---|
| `*ProbeError` (`ErrBackendUnavailable`) | The backend's probe says this host cannot run it; `Cause` is its reason, such as a missing device, firmware or permission. Fix the host, or accept the fallback. |
| `*CapabilityError` for `"probe"` | The backend is no `Prober`, so `Detect` cannot rank it. Select it by name with `enclave.Lookup` instead. |
| nil, yet another backend was selected | It was usable and outranked, or tied with a backend that comes first: locked memory, then the name first in byte order. |

A hardware backend that does not appear in the results at all was not
registered before `Detect` was called.

## Upgrading

See [Upgrading](../README.md#upgrading).

# Sealing and the provider seam — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-14
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Choose the type by access pattern

| Material | Use | Why |
|---|---|---|
| In continuous use (a session key on every packet; a buffer an API keeps) | A memory enclave (`NewMemory`) | It would always be open; sealing buys nothing. Costs at least one locked page for its life. |
| Used intermittently (a credential per request; a root key a few times an hour) | `Sealed` | Plaintext exists only in the enclave an `Open` returns, until you destroy it. At rest it is heap ciphertext; each `Open` takes a fresh locked page. |

Know what sealing does not do. This package never writes recovered plaintext
to the heap, but it does write keys there: every seal and open leaves AES key
schedules in heap memory that is not wiped — the value's DEK in every mode,
and in `ModeRootKey` also the KEK that opens every value of its generation —
so a reader of this process's memory (live, or via swap or a core dump) can
recover recently used values in any mode, and in `ModeRootKey` whole KEK
generations. (Built
with `GOEXPERIMENT=runtimesecret` on linux/amd64 or linux/arm64 (not Android), those
schedules are erased at the next garbage collection instead;
`enclave.KeyScheduleErasure()` reports which build you have. See
[engineering.md](engineering.md#erasure-under-runtimesecret).) With the
default software sealer the keys that unwrap **every** value are in this
process too. A hardware `KeyProtector` in `ModePerOperation` keeps the
long-lived key in the device, which limits the exposure to values sealed or
opened recently. It does not remove that exposure. See
[architecture.md](architecture.md#what-each-mode-buys-against-a-live-memory-reader).

`NewSealer(WithBackend(b))` keeps the wrapping key and the KEKs in `b`
instead; DEKs are always generated in this process
([architecture.md](architecture.md#backends-and-enclave-sources)). That narrows the exposure but never closes it on its own: a key the
backend hands back as bytes still runs AES on the heap. To refuse every
configuration that leaves a schedule exposed, construct with
`WithRequireKeyScheduleErasure()`; `NewSealer` then fails with a
`*KeyScheduleExposedError` naming the first exposed key. Which configurations
pass is in
[backends/architecture.md](../backends/architecture.md#key-schedule-exposure).

## Seal and open

```go
s, err := enclave.NewSealed(ctx, credential) // credential is wiped, on every path
if err != nil {
	return err
}
defer s.Destroy()

// Later, per use: open late, destroy early.
e, err := s.Open(ctx) // decrypted into locked pages, which are then made read-only
if err != nil {
	return err
}
defer e.Destroy()
return e.WithBytes(func(b []byte) error {
	return useCredential(b)
})
```

Inside a request path that has a budget, open through it:

```go
a, err := enclave.ProcessAllocator()
if err != nil {
	return err
}
e, err := s.OpenIn(ctx, a) // ErrBudgetExhausted when over budget; value intact
```

`OpenIn` takes any `Backend` and returns a `Handle`. A backend that cannot
import key material is refused with a `*CapabilityError`, and the value
remains intact. Into the [linux-secretmem](../linux-secretmem/user.md) backend
it decrypts straight into the handle's `memfd_secret` pages, with no
locked-memory or heap copy on the way.

`Seal` and `NewSealed` wipe their input, so they refuse a read-only view (the
slice an opened enclave lends you) with `ErrSealSourceReadOnly`. To re-seal
material that is already locked, seal from the handle instead. The source is
only borrowed and never wiped:

```go
v, err := enclave.NewSealedFrom(ctx, e) // e stays open and intact; destroy it yourself
```

## Bound every call with a context

A provider can block for as long as its device does. Pass a context with a
deadline; an ended context fails a seal with an error matching both
`ErrSealFailed` and `ctx.Err()`, and an open with one matching both
`ErrOpenFailed` and `ctx.Err()`.

A provider verdict that arrives as the context ends is **carried** with the
cancellation in one `*OpenError`, so one error can match `ErrOpenFailed` and a permanent sentinel at
once. Classify the security and lifecycle outcomes first; `ErrOpenFailed` on
its own tells you the value is intact, not that the failure is transient:

```go
ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
defer cancel()
e, err := s.Open(ctx)
switch {
case err == nil:
	defer e.Destroy()
case errors.Is(err, enclave.ErrSealedAuthentication):
	// Tampered or foreign — a security signal, even if ctx also ended. Never retry.
case errors.Is(err, enclave.ErrSealerWiped):
	// This sealer could not serve the open. Not proof the sealer is dead:
	// check s.Openable() (see engineering.md) before concluding anything.
case errors.Is(err, enclave.ErrEnclaveDestroyed):
	// The value was destroyed, or a shutdown sweep destroyed this open's
	// working enclaves. Do not retry.
case errors.Is(err, enclave.ErrOpenFailed):
	// The value is intact, but the error can carry BOTH a cancellation and a
	// provider failure that arrived as the context ended. Classify the
	// provider's cause first: a deleted or disabled key is permanent whether
	// or not the context also ended. Only with no provider cause that rules it
	// out is a cancellation worth retrying with a live context.
	var retry bool
	switch {
	case providerSaysPermanent(err): // your provider's classification (errors.As on its types)
		retry = false
	case providerSaysTransient(err):
		retry = true
	default:
		retry = errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	_ = retry
}
```

The full order, including the resource refusals, is in
[engineering.md](engineering.md#classifying-an-open-failure).

## Release a sealer you no longer need

A default (`ModeRootKey`) `Sealer` you constructed holds locked memory (its
wrapping key and current KEK) until you release it. Destroy it when its values
are no longer needed; retired sealers otherwise accumulate locked pages until
`RLIMIT_MEMLOCK` runs out. A `ModePerOperation` sealer holds no key of its own,
so Destroy there only ends the sealer:

```go
s, err := enclave.NewSealer()
if err != nil {
	return err
}
defer s.Destroy() // values it sealed cannot be opened afterwards
```

Afterwards every seal, open and `Openable` through it reports
`ErrSealerDestroyed`, and a value opens only through the sealer that sealed
it. The `SoftwareProvider` that `NewSealer` creates by
default releases its root as soon as the first unseal has derived the wrapping
key; a provider you inject is never released by the sealer. Release that with
its own lifecycle (`SoftwareProvider.Destroy` for the software one).

## Install a hardware provider

Install once in `main`, before anything seals (the first `NewSealed` otherwise
installs the software default and locks the configuration):

```go
p := newTPMProvider() // an enclave.KeyProtector
s, err := enclave.NewSealer(enclave.WithKeyProtector(p)) // ModePerOperation
if err != nil {
	log.Fatal(err) // ErrInvalidProvider: p is nil
}
if err := enclave.SetSealer(s); err != nil {
	log.Fatal(err) // ErrSealerInstalled
}
```

`WithKeyProtector` selects `ModePerOperation`; `WithRootUnsealer` selects
`ModeRootKey`. The option is typed by the interface its mode needs, so a
provider that cannot serve the mode does not compile.

Implement `HealthReporter` (`Health() error`) on a `KeyProtector` when its key
is not in this process's memory (return `nil`) or when it can tell that a sweep
destroyed it (return `ErrSealerWiped`). `Health` must not block. To write a
provider, see [provider-conformance](../provider-conformance/user.md).

## After a shutdown sweep

`WipeAll` destroys the in-process sealing keys it can reclaim (a key still
borrowed when its context ends survives) but never the sealed values. A
value keeps reporting `IsAlive() == true` (its ciphertext is still there); ask
`Openable()`:

| `Openable()` | Meaning |
|---|---|
| `nil` | Nothing known prevents an open. |
| `ErrSealerWiped` | A sweep destroyed in-process keys this sealer needs (in `ModeRootKey`, its root or current KEK), or the provider's `HealthReporter` reports it; the value can never be opened. |
| `ErrSealerDestroyed` | `Sealer.Destroy` ran; the value can never be opened. |
| `ErrEnclaveDestroyed` | The value itself was destroyed. |
| `ErrOpenabilityUnknown` | A sweep ran and the provider does not implement `HealthReporter`; open it to find out. |

A wiped sealer never re-keys. Construct a new `Sealer` and re-seal from source.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Every seal fails with `ErrSealFailed` wrapping `NewGCMWithRandomNonce requires aes.Block` | Built with `GOEXPERIMENT=boringcrypto` | Not supported; use Go's native FIPS 140-3 module (`GOFIPS140`; see [engineering.md](engineering.md#fips-140-3)). |
| `ErrSealerInstalled` from `SetSealer` | Something sealed first | Install earlier in `main`. |
| `ErrInvalidProvider` from `NewSealer` | A provider option got nil or a typed nil, or both provider options were given | Check the provider variable is set; pass exactly one of `WithKeyProtector` or `WithRootUnsealer`. |
| `ErrOpenFailed` intermittently | Deadline too short, or device/KMS unavailable | If the error matches none of `ErrSealedAuthentication`, `ErrSealerWiped` or `ErrEnclaveDestroyed`, the value is intact. Classify any provider cause first (`errors.As` on its types): never retry a permanent one, even if a cancellation is joined with it; retry a transient one; retry a bare cancellation with a live context. |
| `ErrSealerWiped` | A shutdown `WipeAll` destroyed this sealer's own keys (its root or current KEK in `ModeRootKey`), or the provider returned it. A sweep that destroys only one call's working key gives `ErrEnclaveDestroyed` instead | Check `Openable()` on a value: `ErrSealerWiped` there means the sealer is dead (expected at exit; mid-run, something called `WipeAll` too early). |
| `ErrSealerDestroyed` | Something called `Destroy` on this sealer (or on the `SoftwareProvider` it uses) | Destroy a sealer only after its last use; construct a new one and re-seal from source. |
| `ErrSealerNotConstructed` from `SetSealer` | A `Sealer` not built by `NewSealer`, such as your own implementation of the interface | Construct it with `NewSealer`. |
| `ErrSealerDestroyed` from `SetSealer` | The sealer was destroyed before it was installed | Install a live sealer. |
| `ErrInvalidSealerOption` from `NewSealer` | A nil option | Pass only non-nil options. |
| `ErrInvalidBackend` from `NewSealer` or `OpenIn` | A nil or typed-nil `Backend` | Pass a backend, or `DefaultBackend()`. |
| `*KeyScheduleExposedError` from `NewSealer` | `WithRequireKeyScheduleErasure` and a key (`Name`: `wrapping-key` or `dek`) whose AES schedule would land on the heap | Use a `runtime/secret` build or a confining backend; see [Choose the type](#choose-the-type-by-access-pattern). |
| `ErrSealSourceReadOnly` | `Seal` or `NewSealed` was given a read-only view, such as the slice an opened enclave lends | Use `SealFrom` or `NewSealedFrom` with the handle. |
| `*CapabilityError` from `NewSealer`, `OpenIn` or `SealFrom` | The backend cannot import or does not return the imported bytes, or the source handle does not expose its bytes | Use a backend that implements `Importer`; seal from a handle with `ByteAccess`. |
| `ErrProviderMessageLimit` | `SoftwareProvider` used in `ModePerOperation` past 2^31 seals | Use `ModeRootKey` (rotates KEKs) or a hardware provider. |
| Locked memory grows with traffic | Each `Open` takes a locked page | Destroy opened enclaves promptly; use `OpenIn` so the budget sees it. |

## Upgrading

Migration guidance lives in one place: [Upgrading](../README.md#upgrading).

# Sealing and the provider seam — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-01
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

## Choose the type by access pattern

| Material | Use | Why |
|---|---|---|
| In continuous use (a session key on every packet; a buffer an API keeps) | `MemoryEnclave` | It would always be open; sealing buys nothing. Costs at least one locked page for its life. |
| Used intermittently (a credential per request; a root key a few times an hour) | `SealedEnclave` | Plaintext exists only in the enclave an `Open` returns, until you destroy it. At rest it is heap ciphertext; each `Open` takes a fresh locked page. |

Know what sealing does not do. This package never writes recovered plaintext
to the heap, but it does write keys there: every seal and open leaves that value's AES key schedule in heap
memory that is not wiped, so a reader of this process's memory (live, or via
swap or a core dump) can recover recently used values in any mode. With the
default software sealer the keys that unwrap **every** value are in this
process too. A hardware `KeyProtector` in `ModePerOperation` keeps the
long-lived key in the device, which limits the exposure to values sealed or
opened recently. It does not remove that exposure. See
[architecture.md](architecture.md#what-each-mode-buys-against-a-live-memory-reader).

## Seal and open

```go
s, err := enclave.NewSealed(ctx, credential) // credential is wiped, on every path
if err != nil {
	return err
}
defer s.Destroy()

// Later, per use: open late, destroy early.
e, err := s.Open(ctx) // plaintext decrypted straight into locked pages
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
e, err := s.OpenWith(ctx, a) // ErrBudgetExhausted when over budget; value intact
```

## Bound every call with a context

A provider can block for as long as its device does. Pass a context with a
deadline; an ended context fails a seal with an error matching both
`ErrSealFailed` and `ctx.Err()`, and an open with one matching both
`ErrOpenFailed` and `ctx.Err()`.

A provider verdict that arrives as the context ends is **joined** with the
cancellation, so one error can match `ErrOpenFailed` and a permanent sentinel at
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

## Install a hardware provider

Install once in `main`, before anything seals (the first `NewSealed` otherwise
installs the software default and locks the configuration):

```go
p := newTPMProvider() // your KeyProtector and/or RootUnsealer
s, err := enclave.NewSealer(
	enclave.WithProvider(p),
	enclave.WithMode(enclave.ModePerOperation),
	enclave.WithProviderHealth(func() error { return nil }), // key lives in the device
)
if err != nil {
	log.Fatal(err) // ErrProviderMode: p does not implement KeyProtector
}
if err := enclave.SetSealer(s); err != nil {
	log.Fatal(err) // ErrSealerInstalled
}
```

Supply `WithProviderHealth` when the provider's key is not in this process's
memory (report `nil`) or can tell that a sweep destroyed it (report
`ErrSealerWiped`). The callback must not block. To write a provider, see
[provider-conformance](../provider-conformance/user.md).

## After a shutdown sweep

`WipeAll` destroys the in-process sealing keys it can reclaim (a key still
borrowed when its context ends survives) but never the sealed values. A
value keeps reporting `IsAlive() == true` (its ciphertext is still there); ask
`Openable()`:

| `Openable()` | Meaning |
|---|---|
| `nil` | Nothing known prevents an open. |
| `ErrSealerWiped` | A sweep destroyed in-process keys this sealer needs (in `ModeRootKey`, its root or current KEK), or the provider's health callback reports it; the value can never be opened. |
| `ErrEnclaveDestroyed` | The value itself was destroyed. |
| `ErrOpenabilityUnknown` | A sweep ran and the provider reports no health; open it to find out. |

A wiped sealer never re-keys. Construct a new `Sealer` and re-seal from source.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Every seal fails with `ErrSealFailed` wrapping `NewGCMWithRandomNonce requires aes.Block` | Built with `GOEXPERIMENT=boringcrypto` | Not supported; use Go's native FIPS 140-3 module (`GOFIPS140`; see [engineering.md](engineering.md#fips-140-3)). |
| `ErrSealerInstalled` from `SetSealer` | Something sealed first | Install earlier in `main`. |
| `ErrProviderMode` from `NewSealer` | Provider lacks the mode's interface, or is nil/typed nil | Pick the mode the provider implements; check the provider variable is set. |
| `ErrOpenFailed` intermittently | Deadline too short, or device/KMS unavailable | If the error matches none of `ErrSealedAuthentication`, `ErrSealerWiped` or `ErrEnclaveDestroyed`, the value is intact. Classify any provider cause first (`errors.As` on its types): never retry a permanent one, even if a cancellation is joined with it; retry a transient one; retry a bare cancellation with a live context. |
| `ErrSealerWiped` | A shutdown `WipeAll` destroyed this sealer's keys — or, while a sweep runs, a per-call key; or the provider returned it | Check `Openable()` on a value: `ErrSealerWiped` there means the sealer is dead (expected at exit; mid-run, something called `WipeAll` too early). |
| `ErrProviderMessageLimit` | `SoftwareProvider` used in `ModePerOperation` past 2^31 seals | Use `ModeRootKey` (rotates KEKs) or a hardware provider. |
| Locked memory grows with traffic | Each `Open` takes a locked page | Destroy opened enclaves promptly; use `OpenWith` so the budget sees it. |

## Migrating from v0.6

Every call that can reach a provider takes a `context.Context` first.

```go
// v0.6
s, err := enclave.NewSealed(data)
s2, err := sealer.Seal(data)
e, err := s.Open()
e2, err := s.OpenWith(alloc)

// v0.7
s, err := enclave.NewSealed(ctx, data)
s2, err := sealer.Seal(ctx, data)
e, err := s.Open(ctx)
e2, err := s.OpenWith(ctx, alloc)
```

Provider implementations gain a context on every method and must honor it:

```go
// v0.6
func (p *MyProvider) Protect(key []byte) ([]byte, error)
func (p *MyProvider) Unprotect(blob, key []byte) error
func (p *MyProvider) UnsealRoot(dst []byte) error

// v0.7
func (p *MyProvider) Protect(ctx context.Context, key []byte) ([]byte, error)
func (p *MyProvider) Unprotect(ctx context.Context, blob, key []byte) error
func (p *MyProvider) UnsealRoot(ctx context.Context, dst []byte) error
```

Behavior changes to check for:

- A `ModePerOperation` provider's infrastructure error on open now arrives
  joined under the new `ErrOpenFailed` (still reachable with `errors.Is`/`As`).
  Code that matched only the provider's error keeps working; code that treated
  "anything not `ErrSealedAuthentication`" as one class can now match
  `ErrOpenFailed`.
- `(*SealedEnclave).Destroy` no longer waits for an `Open` in flight.
- `providertest.TestProvider(cfg)` became `TestProvider(ctx, cfg)`; see
  [provider-conformance](../provider-conformance/user.md#migrating-from-v06).

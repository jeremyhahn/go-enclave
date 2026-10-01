# Provider conformance — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-01
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

For authors of a `KeyProtector` and/or `RootUnsealer` — a TPM, HSM or cloud-KMS
provider — written in your own module.

## Before you start

- Decide which modes you serve. `ModePerOperation` needs a `KeyProtector`
  (`Protect`/`Unprotect` on every seal and open); `ModeRootKey` needs a
  `RootUnsealer` (one `UnsealRoot` per `Sealer`). Implement **only** what you
  serve: an extra method makes `NewSealer` accept a mode you never built.
- `Unprotect` must authenticate: refuse anything your `Protect` did not
  produce with an error matching `enclave.ErrSealedAuthentication`. A
  decryption-only primitive (bare RSA-OAEP) must be composed with a signature.
- Copy your library's decrypted bytes into the caller's slice and wipe your
  own copy before returning.
- Honor the context: refuse an already-ended one before device work, with an
  error matching `ctx.Err()`; write nothing and consume nothing on a refusal.

## Run the suite

```go
package tpmprovider_test

import (
	"testing"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"
)

func TestConformance(t *testing.T) {
	err := providertest.TestProvider(t.Context(), providertest.Config{
		New:   func() (any, error) { return NewTPMProvider(testDevice(t)) },
		Modes: []enclave.Mode{enclave.ModePerOperation},
		Logf:  t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
}
```

Run it on Linux at least once: that is the only platform where the residue
sweep (the only check that can see a retained **copy**) runs. Always pass
`Logf` and read it with `go test -v` — it is where skipped and unmeasurable
checks are reported.

## Reading a failure

```go
var pe *providertest.PropertyError
switch {
case errors.Is(err, providertest.ErrInvalidConfig):
	// Your Config is wrong (New nil, Modes empty or invalid).
case errors.Is(err, providertest.ErrAborted):
	// The context ended first; the run is incomplete. Raise the deadline.
case errors.As(err, &pe):
	// At least one assertion failed; err joins one *PropertyError per failed
	// assertion (several can share a Property). errors.As returns the first.
	t.Fatalf("%s: %s", pe.Property, pe.Detail)
}
```

## Legitimate relaxations

| Field | When to set it | What you give up |
|---|---|---|
| `SkipResidueSweep: "<reason>"` | A transit you cannot wipe — e.g. a KMS whose plaintext arrives in an HTTP response body owned by `net/http` | Retention by **copy** is unmeasured; the reason is logged. |
| `SingleUseRoot: "<reason>"` | `UnsealRoot` consumes a one-shot handle or session on success | The full-width-write proof and the root-destination spy, which need a second call; the reason is logged. |

Never set either to silence a failure you have not explained.

## Troubleshooting

| Failure | Usual cause |
|---|---|
| mode/interface pairing — "ACCEPTED … which Config.Modes does not claim" | The type has a method of the other interface (often a stub `UnsealRoot`). Remove it, or claim and implement the mode. |
| a blob this provider did not produce is refused | `Unprotect` decrypts without authenticating, or returns an infrastructure error instead of `ErrSealedAuthentication` for a bad blob. |
| Protect does not retain the caller's key slice | The provider stored the `key` slice instead of copying it. |
| Unprotect does not write into a destination the caller has finished with | The provider kept the destination slice and writes to it later. |
| … refuse a context that has already ended | The provider ignores `ctx`, or reports cancellation as `ErrSealedAuthentication`. |
| no copy of the key is findable … after Unprotect returns | A decrypted transient was not wiped (or is retained). |
| UnsealRoot writes a root across the whole destination | A placeholder root (all-zero or constant), or a partial write. |
| Run reported aborted, no property failed | `ctx` deadline too short for your device, or a call that never returns. |

## Migrating from v0.6

```go
// v0.6
err := providertest.TestProvider(providertest.Config{ /* ... */ })

// v0.7
err := providertest.TestProvider(t.Context(), providertest.Config{ /* ... */ })
```

Your provider's methods also take a context first (`Protect(ctx, key)`,
`Unprotect(ctx, blob, key)`, `UnsealRoot(ctx, dst)`), and the suite now checks
that they refuse an already-ended one. See
[sealing](../sealing/user.md#migrating-from-v06).

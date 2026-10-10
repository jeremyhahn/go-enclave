# Provider conformance — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-09
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
  If `Protect` needs no secret, set `PublicKey` and give the suite a `Forge`
  that builds the blob an attacker holding your public key could
  ([below](#public-key-providers)).
- Be safe for concurrent use: a `Sealer` calls you from many goroutines, and
  the suite runs round trips from several at once.
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

Run it on Linux: that is the only platform where the residue sweep (the only
check that can see a retained **copy**) runs. Elsewhere the run returns an
error matching `ErrNotMeasured` unless you set `SkipResidueSweep` (for example
only when `runtime.GOOS != "linux"`). Always pass `Logf` and read it with
`go test -v` — it is where skipped checks are reported.

### Public-key providers

The tampered-blob cases cannot catch a bare public-key wrap: its padding or tag
refuses every malformed blob, but opens a well-formed one anyone encrypted to
the public key. Declare the shape and play the attacker:

```go
cfg.PublicKey = true
cfg.Forge = func(p enclave.KeyProtector, key []byte) ([]byte, error) {
	// Only what an attacker has: your public key (and, if Unprotect verifies
	// a signature, a signing key of the attacker's own).
	return wrapToPublicKey(p.(*TPMProvider).PublicKey(), key)
}
```

`Unprotect` must refuse the forged blob with `ErrSealedAuthentication`.
`PublicKey` without `Forge` returns `ErrNotMeasured` unless `SkipForgery`
records why.

## Reading a failure

```go
var pe *providertest.PropertyError
switch {
case errors.Is(err, providertest.ErrInvalidConfig):
	// Your Config is wrong (New nil, Modes empty or invalid).
case errors.Is(err, providertest.ErrAborted):
	// The context ended first; the run is incomplete. Raise the deadline.
case errors.Is(err, providertest.ErrNotMeasured):
	// A property could not be measured (e.g. the residue sweep off Linux, or
	// PublicKey without Forge). Measure it, or accept it via SkipResidueSweep
	// or SkipForgery.
case errors.As(err, &pe):
	// At least one assertion failed; err joins one *PropertyError per failed
	// assertion (several can share a Property). errors.As returns the first.
	t.Fatalf("%s: %s", pe.Property, pe.Detail)
}
```

## Legitimate relaxations

| Field | When to set it | What you give up |
|---|---|---|
| `SkipResidueSweep: "<reason>"` | A transit you cannot wipe — e.g. a KMS whose plaintext arrives in an HTTP response body owned by `net/http` — or a host where the sweep cannot run (non-Linux) | Retention by **copy** is unmeasured; the reason is logged. Without it an unmeasurable sweep returns `ErrNotMeasured`. |
| `SkipForgery: "<reason>"` | A public-key provider whose forgery refusal is proved elsewhere, e.g. the device's own test suite | Whether `Unprotect` opens a blob built from your public key is unmeasured; the reason is logged. Without it, `PublicKey` without `Forge` returns `ErrNotMeasured`. |
| `SingleUseRoot: "<reason>"` | `UnsealRoot` consumes a one-shot handle or session on success | The full-width-write proof and the root-destination spy, which need a second call; the reason is logged. |

Never set either to silence a failure you have not explained.

## Troubleshooting

| Failure | Usual cause |
|---|---|
| mode/interface pairing — "ACCEPTED … which Config.Modes does not claim" | The type has a method of the other interface (often a stub `UnsealRoot`). Remove it, or claim and implement the mode. |
| a blob this provider did not produce is refused | `Unprotect` decrypts without authenticating, or returns an infrastructure error instead of `ErrSealedAuthentication` for a bad blob. |
| a blob forged from the provider's public key is refused | `Unprotect` opens a public-key wrap without verifying a signature or MAC an attacker cannot make. |
| Protect and Unprotect are safe for concurrent use | Shared, unsynchronized state: a scratch buffer, a session or a handle that concurrent calls overwrite. |
| Protect does not retain the caller's key slice | The provider stored the `key` slice instead of copying it. |
| Unprotect does not write into a destination the caller has finished with | The provider kept the destination slice and writes to it later. |
| … refuse a context that has already ended | The provider ignores `ctx`, or reports cancellation as `ErrSealedAuthentication`. |
| no copy of the key is findable … after Unprotect returns | A decrypted transient was not wiped (or is retained). |
| UnsealRoot writes a root across the whole destination | A placeholder root (all-zero or constant), or a partial write. |
| Run reported aborted, no property failed | `ctx` deadline too short for your device, or a call that never returns. |
| `ErrNotMeasured` — forged-blob check not run | `PublicKey` is set without `Forge`. Set `Forge`, or `SkipForgery` with the reason. |
| `ErrNotMeasured` — residue sweep not run | Not Linux, `RLIMIT_MEMLOCK` too low for two locked pages, or `/proc/self/mem` unreadable. Fix the host, or set `SkipResidueSweep` with the reason. |

## Upgrading

Migration guidance lives in one place: [Upgrading](../README.md#upgrading).

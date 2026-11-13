# Backend conformance — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-11-12
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

Check that a backend you wrote honors the [backend seam](../backends/user.md)
before anyone relies on it. The suite is one function, `backendtest.TestBackend`,
and runs in your own test binary ([architecture](architecture.md)).

## Prerequisites

- A backend type that implements `enclave.Backend` and a factory that returns a
  fresh one.
- Linux, for the residue sweep. Elsewhere the sweep cannot run; see
  [Skip the residue sweep](#skip-the-residue-sweep).
- `go test -race`: the concurrency check is only complete under the race
  detector.

## Run it

```go
func TestBackendConformance(t *testing.T) {
	err := backendtest.TestBackend(t.Context(), backendtest.Config{
		New: func() (enclave.Backend, error) { return mybackend.Open() },
		BackendCapabilities: []enclave.Capability{
			enclave.CapabilityImport,
		},
		Handles: []backendtest.HandleCase{{
			Name:       "material",
			Import:     []enclave.ImportOption{enclave.WithPurpose(enclave.PurposeMaterial)},
			ImportSize: 32,
			Capabilities: []enclave.Capability{
				enclave.CapabilityBytes,
			},
		}},
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
}
```

## Describe your backend exactly

The suite checks claims in both directions, so list exactly what you
implement:

- **`BackendCapabilities`**: what the backend itself offers: `CapabilityImport`,
  `CapabilitySweep`, `CapabilityConfine`, `CapabilityAttest`, `CapabilityProbe`.
- **One `HandleCase` per kind of handle** the backend makes, each with its own
  `Capabilities` (`CapabilityBytes`, `CapabilityFreeze`, `CapabilitySign`,
  `CapabilityDecrypt`, `CapabilityAEAD`, `CapabilityDerive`,
  `CapabilityAttest`). A device that makes both signing keys and AES keys has
  two cases.
- **A case makes its handle one of two ways.** Set `New` for a handle the device
  makes itself (a generated key), or `Import` and `ImportSize` for a handle
  made by importing random material with the options you give. Not both.
  Material from `New` should be random too: the residue sweep cannot tell one
  repeated byte, such as a zeroed region, from the rest of the process.

`ExampleTestBackend` in [`backendtest/example_test.go`](../../backendtest/example_test.go)
is a complete run you can copy: it certifies the shipped locked-memory backend
(`enclave.DefaultBackend()`), which claims only `CapabilityProbe` and makes its
handles with a `New` case, and `go test ./backendtest/` runs it. It also shows
on `pkg.go.dev` under `TestBackend`.

## Certify attestation

If the backend or a handle is an `Attester`, set `VerifyEvidence` to what your
verifier does: return nil when the evidence binds the nonce, an error when it
does not. Without it the suite refuses the capability as unchecked, because
evidence that merely differs between calls need not bind the nonce.

## Skip the residue sweep

On a platform without the sweep, or where it cannot measure, set
`SkipResidueSweep` to the reason. The run logs it through `Logf`; without it the
result is a `*NotMeasuredError`.

## Read the result

`TestBackend` returns nil, or an error to print. Tell the cases apart with
`errors.Is` and `errors.As`, and fail the test on every non-nil error:

```go
var fe *backendtest.FindingsError
switch {
case err == nil:
case errors.Is(err, backendtest.ErrInvalidConfig):
	t.Fatal(err) // fix the test: the config could not be run
case errors.Is(err, backendtest.ErrUncheckedCapability):
	t.Fatal(err) // a declared capability the suite cannot exercise
case errors.Is(err, backendtest.ErrAborted):
	t.Fatal(err) // the context ended first; the findings printed are real
case errors.As(err, &fe):
	for _, f := range fe.Findings {
		t.Error(f)
	}
default:
	t.Fatal(err)
}
```

`*UncheckedCapabilityError` comes back on its own, before any check, for a
config that claims what the suite cannot exercise, and inside a
`FindingsError` when a check finds it. `*AbortedError` always comes inside a
`FindingsError`.

## Troubleshooting

| Error | Cause and fix |
|---|---|
| `ErrInvalidConfig` (`*ConfigError`) | `Field` says which field is wrong: no `New`, no `Handles`, a case with an empty or duplicate name, a case setting both or neither of `New` and `Import`, a non-positive `ImportSize`, or a repeated capability. Fix the config. |
| `ErrUncheckedCapability` | The suite cannot exercise a capability you declared: an unknown one, `CapabilityFreeze` without `CapabilityBytes`, `CapabilityImport` with no imported case, a signing key that is not ECDSA, RSA or Ed25519, a decryption key that is not RSA, a derived key it cannot compare, or an `Attester` without `VerifyEvidence`. `Reason` says which; add what it names or stop claiming the capability. |
| `ErrNotMeasured` | The residue sweep could not run, or the material is under 16 bytes or one repeated byte. Fix the host, give the case random material, or set `SkipResidueSweep` with a reason. |
| `ErrAborted` | The context ended first. Give the run a longer deadline; findings reported with it are real. |
| `*PropertyError` | The backend broke the seam. `Property` names the check and `Detail` says what was observed; the list is in [engineering.md](engineering.md#what-it-checks). |

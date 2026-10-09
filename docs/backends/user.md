# Backends — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-08
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

A backend is what holds an enclave's material. Locked memory, the
[`MemoryEnclave`](../locked-memory/user.md), is the default and the only one in
this module; hardware backends (TEEs, secure elements, TPMs, GPU confidential
computing) ship as their own modules. This release declares the seam; using a
backend other than locked memory for sealing and allocation arrives with its
wiring ([architecture](architecture.md)).

## Prerequisites

None for locked memory: it is always registered, under
`enclave.LockedMemoryBackendName` (`"locked-memory"`). A hardware backend needs
its module and the hardware.

## Register a backend and select it by name

Nothing registers itself. Construct the backend in `main` and register it, so
configuration can name it:

```go
b, err := tdx.New() // a hardware backend module
if err != nil {
	return err
}
if err := enclave.Register(b); err != nil {
	return err
}

backend, err := enclave.Lookup(cfg.Backend) // e.g. "tdx" or "locked-memory"
if err != nil {
	return err
}
```

`enclave.BackendNames()` lists what is registered; log it at startup.

## Ask what a handle can do

Every enclave is an `enclave.Handle`: `Size`, `IsAlive`, `Destroy` and
`Backend`. Anything else is a capability; test for it with a type assertion:

```go
if ba, ok := h.(enclave.ByteAccess); ok {
	err = ba.WithBytes(func(b []byte) error { return use(b) })
}
if signer, ok := h.(crypto.Signer); ok {
	sig, err = signer.Sign(rand.Reader, digest, crypto.SHA256)
}
```

Material in a secure element never reaches the process, so its handles sign
(`crypto.Signer`), decrypt (`crypto.Decrypter`) or seal (`enclave.AEAD`)
instead of offering their bytes. Once a handle is destroyed, each of those
operations returns `enclave.ErrEnclaveDestroyed`.

## Reach a backend's own API

A backend's type is its native API. Operations the seam does not name, such as
signing that takes a context or ECDH key agreement, live there. Reach it with
a type assertion, or with `enclave.As` when the value may wrap it:

```go
var t *tdx.Backend
if enclave.As(backend, &t) {
	report, err := t.Report(reportData)
	// …
}
```

## Troubleshooting

| Error | Cause and fix |
|---|---|
| `ErrInvalidBackend` | `Register` got a nil backend, or a name that is not 1 to 64 bytes of `a-z`, `0-9`, `-` and `.`, starting and ending with a letter or digit. |
| `*BackendExistsError` | The name is taken. Register each backend once, in `main`; `"locked-memory"` is always taken. |
| `*BackendNotRegisteredError` | `Lookup` of a name nobody registered: the configuration names a backend `main` did not register. |
| `*CapabilityError` | The handle or backend lacks what the operation needs, such as byte access to a secure element's key. Choose a backend that provides it; nothing falls back silently. |

## Upgrading

See [Upgrading](../README.md#upgrading).

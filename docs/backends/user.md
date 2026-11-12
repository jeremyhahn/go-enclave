# Backends — user guide

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-11-12
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

A backend is what holds an enclave's material. Locked memory, the
[memory enclave](../memory-enclave/user.md), is the default. This module also
ships the [linux-secretmem](../linux-secretmem/user.md) backend
(`enclave.NewSecretMemory`). Hardware backends ship as their own modules:
[arm-trustzone](#arm-trustzone) today, with TEEs, secure elements and GPU
confidential computing [proposed](#proposed-hardware-backends). A sealer can keep its keys in a backend
(`WithBackend`) and `Sealed.OpenIn` can open into one; see
[sealing](../sealing/user.md) ([architecture](architecture.md)).

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

To let go-enclave pick instead of configuration, call `enclave.Detect(ctx)`
after registering: it selects the most secure registered backend this host
can run, locked memory when no other can
([backend detection](../backend-detection/user.md)).

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

## Check a backend you wrote

Run the conformance suite from your backend's tests:
[backend conformance](../backend-conformance/user.md).

## arm-trustzone

`github.com/jeremyhahn/go-enclave/backends/armtrustzone` reaches OP-TEE on
Arm through the Linux TEE driver (`/dev/tee0`), in pure Go
([design](arm-trustzone-design.md)). It needs Linux, an OP-TEE kernel driver
and the trusted application whose interface the design describes
([The TA interface](arm-trustzone-design.md#the-ta-interface)); elsewhere
`Connect` returns `*armtrustzone.PlatformError`. Its handles are byte-access memory
enclaves filled from the TEE's random number generator:

```go
b, err := armtrustzone.Connect("/dev/tee0") // opens a session, probes the TA
if err != nil {
	return err
}
defer b.Close()
h, err := b.Random(ctx, 32) // 32 bytes from the secure world
```

To register it by name without connecting, pass `armtrustzone.Connector{}` to
`enclave.Register` and call its `Connect` after `Lookup`. `Connector` is no
`Prober`, so `Detect` passes it over; for `Detect` to select the backend,
register the connected `*armtrustzone.Backend`, which probes the TA and ranks
2. A failure is the module's typed error:
`*DeviceError` (the device or an ioctl failed; `Op` says which),
`*SessionError` (the TA is missing or refused the session), `*InterfaceError`
(the TA speaks another interface version), `*CommandError` and
`*ShortRandomError` (the TA failed or returned too few bytes), `*SizeError`
(`Random` of fewer than 1 byte) and `ErrBackendClosed`.

### Seal keys with the TA

`(*Backend).KeyProtector()` is an `enclave.KeyProtector` whose key never
leaves the trusted application: `Protect` seals with the TA's SEAL command and
`Unprotect` opens with UNSEAL. Give it to a sealer:

```go
b, err := armtrustzone.Connect("/dev/tee0")
if err != nil {
	return err
}
defer b.Close() // the sealer's calls fail with ErrBackendClosed after this
s, err := enclave.NewSealer(enclave.WithKeyProtector(b.KeyProtector())) // ModePerOperation
if err != nil {
	return err
}
```

A blob opens only on the device and TA that sealed it. The TA release the
test fixture pins (`v0.4.2-alpha`) does not have SEAL and UNSEAL yet; against
a TA without them, `Connect` and `Random` work but the first seal fails with a
`*CommandError` for command `0x3`.

## Proposed hardware backends

These are design proposals. No code exists for them yet:

| Backend | Proposal |
|---|---|
| AMD SEV-SNP | [amd-sev.md](amd-sev.md) |
| Intel TDX | [intel-tdx.md](intel-tdx.md) |
| NXP i.MX 95 EdgeLock Enclave | [imx-edgelock-enclave.md](imx-edgelock-enclave.md) |
| NVIDIA Blackwell confidential computing | [nvidia-blackwell.md](nvidia-blackwell.md) |

## Troubleshooting

| Error | Cause and fix |
|---|---|
| `ErrInvalidBackend` | `Register` got a nil backend, or a name that is not 1 to 64 bytes of `a-z`, `0-9`, `-` and `.`, starting and ending with a letter or digit. |
| `*BackendExistsError` | The name is taken. Register each backend once, in `main`; `"locked-memory"` is always taken. |
| `*BackendNotRegisteredError` | `Lookup` of a name nobody registered: the configuration names a backend `main` did not register. |
| `*CapabilityError` | The handle or backend lacks what the operation needs, such as byte access to a secure element's key. Choose a backend that provides it; nothing falls back silently. |
| `*armtrustzone.CommandError` with `Command` `0x3` (code `0xffff000a` or `0xffff0006`) from a seal | The trusted application has no SEAL command. Install a TA release that has SEAL and UNSEAL. |
| `enclave.ErrSealedAuthentication` from an open through the arm-trustzone `KeyProtector` | The blob was sealed by another device or TA, or was altered. It cannot be opened here; re-seal from source on this device. |

## Upgrading

See [Upgrading](../README.md#upgrading).

# arm-trustzone backend — design

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-11-13
> Conflicts with this document are defects. The code in [`backends/armtrustzone`](../../backends/armtrustzone) is canonical: fix this document to match it.
> The design of the backend that reaches OP-TEE through the [backend seam](architecture.md). Its API is in [user](user.md#arm-trustzone) and [engineering](engineering.md#arm-trustzone); its integration harness is [backend-conformance](../backend-conformance/engineering.md#the-arm-trustzone-harness).

## Problem

The locked-memory and secretmem backends keep material in the memory of the
process that uses it. On Arm, TrustZone splits the processor into a normal
world, which runs Linux and the program, and a secure world, which runs a
Trusted Execution Environment (TEE) such as OP-TEE. Code and keys in the
secure world are out of reach of the normal-world kernel and of every process.

The `arm-trustzone` backend connects go-enclave to a Trusted Application (TA)
in OP-TEE. It provides two things:

- **Random bytes from the secure world.** `Random(ctx, n)` fills a memory
  enclave handle with bytes the TA's random number generator produced.
- **Key sealing in the secure world.** `KeyProtector()` returns an
  `enclave.KeyProtector` whose sealing key lives in the TA, so a sealer's
  data-encryption keys are wrapped by a key the normal world never holds.

Neither keeps the caller's bytes in the secure world. A handle from `Random`
is normal-world memory from `enclave.NewMemorySized`, readable by the
normal-world process and kernel like any memory enclave. Holding material in
secure-world RAM through trusted-firmware's vault trusted application is
planned ([SPEC](../SPEC.md#features)); the `KeyProtector` is to move to
go-xkms ([removal](../SPEC.md#key-operation-api-removal)).

## Shape

| Piece | What it is |
|---|---|
| `Connect(endpoint) (*Backend, error)` | Opens the TEE device, checks it is a GlobalPlatform TEE, opens a session with the TA by UUID and checks its interface with GET_INFO. |
| `*Backend` | An `enclave.Backend` and `enclave.Prober` named `arm-trustzone`, rank 2. Its native API is `Random`, `KeyProtector` and `Close`. |
| `Connector` | A value to register by name before connecting. Its `Connect` returns the backend as an `enclave.Backend`. It is no `Prober`. |
| handles from `Random` | Memory enclaves (`ByteAccess`) whose `Backend()` is the `*Backend` that filled them. |
| `*KeyProtector` | An `enclave.KeyProtector` and `enclave.HealthReporter` for `ModePerOperation`, over the TA's SEAL and UNSEAL commands. |

The backend implements `Prober`, so [`Detect`](../backend-detection/architecture.md)
can select it. Rank 2 places it above secretmem (1) and locked memory (0):
its random bytes come from the secure world, beyond the reach of this
process's memory. It is not an `Importer`, `Sweeper`, `Attester` or
`Confiner`, so `OpenIn` and `WithBackend` refuse it with a
`*CapabilityError` ([a missing capability](architecture.md#a-missing-capability)).

## The TA interface

The TA is built outside this repository. Its interface, which this client
drives, is fixed by its header `tfw_ta.h` at the release the fixture pins
(`TRUSTED_FIRMWARE_TAG` in [`scripts/tool-pins.sh`](../../scripts/tool-pins.sh)):

| Item | Value | Parameters |
|---|---|---|
| UUID | `23751b49-3a76-4e49-b63c-e5853742fa1f` (RFC 9562, version 4) | – |
| `GET_INFO` | `0x00000001` | param 0 `VALUE_OUTPUT`: `a` the interface version, `b` the flags |
| `GET_RANDOM` | `0x00000002` | param 0 `MEMREF_OUTPUT`: 1 to 4096 bytes |
| `SEAL` | `0x00000003` | param 0 `MEMREF_INPUT`: plaintext; param 1 `MEMREF_INPUT`: associated data, may be empty; param 2 `MEMREF_OUTPUT`: the sealed blob |
| `UNSEAL` | `0x00000004` | param 0 `MEMREF_INPUT`: the sealed blob; param 1 `MEMREF_INPUT`: associated data; param 2 `MEMREF_OUTPUT`: the plaintext |
| Interface version | `1` | – |
| Info flags | `0` | – |
| Random size | `1` to `4096` | – |

SEAL and UNSEAL return `TEE_ERROR_SHORT_BUFFER` (`0xFFFF0010`) with the size
they needed in param 2's size; UNSEAL returns `TEE_ERROR_MAC_INVALID`
(`0xFFFF3071`) for a tampered blob. A TA release without SEAL answers it as
it answers any command it does not define.

The client accepts only interface version 1 with flags 0, at `Connect` and in
`Probe`. Anything else is an `*InterfaceError`, so a newer TA is never driven
by an older client.

## Data flow

1. `Connect(endpoint)` opens the device (`/dev/tee0`), checks
   `TEE_IOC_VERSION` reports a GlobalPlatform TEE, opens a public-login session
   with the TA by its UUID, and runs GET_INFO. A missing device, a missing TA,
   a refused session or another interface version is a typed error, and
   everything opened so far is closed.
2. `Probe(ctx)` runs GET_INFO again. `Detect` calls it.
3. `Random(ctx, n)` refuses `n < 1` before the TA is called, allocates a
   memory enclave of `n` bytes and fills it through GET_RANDOM in chunks of
   at most 4096 bytes. On any failure, a cancelled `ctx` included, the
   enclave is destroyed and no handle is returned.
4. Calls to the TA are serialized on the session. A caller waiting for the
   session leaves with its context's error as soon as the context ends. A
   cancelled `ctx` during a call issues `TEE_IOC_CANCEL`.
5. `Close` ends the session and closes the device. It waits out a call in
   flight and is idempotent; later calls return `ErrBackendClosed`.

## Trust boundary

The bytes cross a buffer shared between the secure world and the normal
world: the `MEMREF` parameter. Whatever the TA holds in the secure world
before it writes that buffer is the TA's to wipe. On the go-enclave side:

- **Registered memory.** Where the driver claims `TEE_GEN_CAP_REG_MEM`, the
  handle's own locked, guarded pages are registered with
  `TEE_IOC_SHM_REGISTER` and the TA writes into them. There is no copy, and
  the handle's own zeroization on `Destroy` wipes the bytes. Each buffer whose
  address is passed to the driver is pinned (`runtime.Pinner`) until the
  driver releases it.
- **Driver shared memory.** Otherwise the backend allocates driver shared
  memory (`TEE_IOC_SHM_ALLOC`, `mmap`), copies each chunk into the handle, and
  zeroes the shared buffer after each copy and before `munmap`, on every path,
  an error or a cancelled `ctx` included.

`Random` keeps nothing in the secure world. The bytes leave it as soon as
they are produced, and the handle in the normal world is their only holder.

## KeyProtector

`(*Backend).KeyProtector()` returns an `enclave.KeyProtector` and
`enclave.HealthReporter` for `ModePerOperation`: `Protect` runs SEAL on the
key and `Unprotect` runs UNSEAL on the blob. The key the blob is sealed under
lives in the TA; the blob is a generic provider blob, opaque to go-enclave.

- **Associated data.** Both commands carry the fixed ASCII label
  `go-enclave v1 TrustZone KeyProtector`, so a blob the TA sealed for another
  client never opens as a go-enclave key.
- **SEAL's output.** The output buffer starts at `len(key) + 64` bytes. On
  `TEE_ERROR_SHORT_BUFFER` it is retried once, at the size the TA reported,
  and refused above 4096 bytes. Any other failure, or a reported size of zero
  or above the buffer, is a `*CommandError` (`ErrCommandFailed`).
- **UNSEAL's output.** When the driver registers memory, the TA writes into
  the caller's `key` directly. Otherwise the plaintext lands in driver shared
  memory, is copied into `key`, and the shared memory is wiped.
- **Error mapping.** On UNSEAL, `TEE_ERROR_MAC_INVALID`,
  `TEE_ERROR_BAD_FORMAT` (`0xFFFF0005`), `TEE_ERROR_SHORT_BUFFER` and a
  plaintext of a length other than `len(key)` all match
  `enclave.ErrSealedAuthentication`. So do an empty blob, a blob above 4096
  bytes and an empty `key`, which are refused before the TA is called. Any
  other result, `TEE_ERROR_BAD_PARAMETERS` among them, is a `*CommandError`.
  Driver failures are a `*DeviceError`, and a closed backend is
  `ErrBackendClosed`. `key` is zeroed on every failure.

It meets the [provider contract](../sealing/engineering.md#provider-contract):

- UNSEAL authenticates every blob.
- `Unprotect` writes exactly `len(key)` bytes into the caller's `key`.
- `Protect` keeps no key, and its copy in driver shared memory is wiped.
- The blob is copied, never kept or changed.
- An ended context is refused before the TA is called, and one ending during
  the call cancels it.
- Infrastructure failures are the backend's own typed errors.
- Concurrent calls are serialized by the session lock.
- `Health` returns nil without blocking: a failure to reach the TA is
  reported by the call that needs it.

A blob opens only on the device and TA that sealed it.

## Testing

### Testing without the fixture

The client reaches the kernel through a small driver seam: open, ioctl,
shared-memory register, mmap, munmap and close. An ordinary `go test`
replaces it with a fake TEE driver (`faketee_linux_test.go`) whose TA seals
with AES-GCM. The fake runs the provider suite, the parameter wiring of SEAL
and UNSEAL, the short-buffer retry, tampered blobs and cancellation. It runs
each with registered memory and with driver shared memory, and fails if any
shared memory or session outlives the call.

Other unit tests check the ioctl struct layouts, offsets and numbers against
the pinned [`tee.h`](../reference/linux-uapi-tee.h), the `TEEC_UUID` byte
order of [RFC 9562](../reference/rfc9562.txt), the chunk plan, GET_INFO's
acceptance, and `Connect` on a missing device and off Linux.

### Conformance on OP-TEE

The fake proves the client's use of the driver ABI. Conformance runs against
a real OP-TEE secure world. `conformance_optee_test.go` (build tag `optee`)
connects to `GO_ENCLAVE_OPTEE_ENDPOINT` and runs:

- `TestBackendConformance_OnOPTEE`: `backendtest.TestBackend` with the probe
  and a random-filled handle case;
- `TestKeyProtectorConformance_OnOPTEE`: `providertest.TestProvider` against
  the `KeyProtector`.

`make integration-test-arm-trustzone` builds the test as a static
`linux/arm64` binary with `CGO_ENABLED=0`, shares it with the guest of the
pinned OP-TEE fixture (TF-A, OP-TEE OS and Linux on QEMU `virt`), and runs it
there. The fixture image is pinned by digest (`OPTEE_FIXTURE_IMAGE` in
[`scripts/tool-pins.sh`](../../scripts/tool-pins.sh)), so CI uses its prebuilt
stack and never builds it. A missing endpoint fails the run; it never skips.

### SEAL on the pinned TA

GET_INFO cannot tell whether a TA has SEAL: a TA reports interface version 1
and flags 0 with SEAL and without it, and no error code proves SEAL absent,
since a TA with SEAL can answer `TEE_ERROR_BAD_PARAMETERS` to a malformed SEAL
call and to an unknown command alike. The fixture therefore declares it in
`GO_ENCLAVE_OPTEE_SEAL`:

| Value the test sees | Behavior of `TestKeyProtectorConformance_OnOPTEE` on a SEAL error |
|---|---|
| empty or `required` | Fails. |
| `absent:<release>` | Skips on `TEE_ERROR_BAD_PARAMETERS` or `TEE_ERROR_NOT_SUPPORTED` from SEAL, only when `<release>` is `v0.4.2-alpha` (`opteeSealAbsentRelease`), the pinned release known to lack SEAL. Fails otherwise. A new pin without SEAL must raise both. |
| anything else | Fails. |

`make integration-test-arm-trustzone` with `GO_ENCLAVE_OPTEE_SEAL` empty, the
default, makes the fixture pass `absent:<TRUSTED_FIRMWARE_TAG>`; set it to
`required` to turn the skip into a failure. A SEAL that works runs the suite
under every value. `TestSealDecision` runs this decision against the fake
TEE.

## Design choices

### A nested module

The backend is the nested module `backends/armtrustzone`, with its own
`go.mod`, released under prefixed tags (`backends/armtrustzone/vX.Y.Z`). It
requires the root module, never the reverse, with no `replace` or `go.work`.

- **Why not the root module.** The root module holds no hardware-specific
  code and keeps `golang.org/x/sys` as its only dependency.
- **Why not a separate repository.** The backend, the seam it implements and
  the `backendtest` harness change together in one pull request and one CI
  run. A separate repository would need a second CI and a cross-repository
  version bump for every seam change.
- **Cost.** A release that changes the backend cuts a second, prefixed tag. A
  root API change must be tagged before the nested module can require it. The
  build gates cover each module listed in `BACKEND_MODULES`.

### Pure Go over the TEE ioctls

The client speaks the Linux TEE subsystem's ioctl interface
(`include/uapi/linux/tee.h`) through `golang.org/x/sys/unix`, with the
GlobalPlatform TEE Client API's semantics (`TEEC_InitializeContext`,
`TEEC_OpenSession`, `TEEC_InvokeCommand`, the `TEEC_Operation` parameter
types, `TEEC_UUID`). It does not use cgo over OP-TEE's `libteec`.

- **Why.** The test binary stays static and runs in the guest as built. The
  build needs no cross C toolchain or arm64 sysroot. The module adds no
  dependency beyond `golang.org/x/sys`. Registered shared memory (the
  [trust boundary](#trust-boundary)) is reachable directly.
- **Cost.** The module carries its own client of the ioctl ABI. Its struct
  layouts and ioctl numbers are checked against the pinned kernel header, and
  a kernel bump re-checks them. `libteec`'s behavior (session login, parameter
  encoding, the RFC 9562 byte order of `TEEC_UUID`) is reimplemented rather
  than inherited.

### The fixture runs in its own image

The `optee` CI job runs in a prebuilt OP-TEE QEMU fixture image, not in
go-enclave's toolchain image. The fixture's host packages belong to the
fixture; copying them into the toolchain image would grow every other job's
image and drift from the pin. A local run without `OPTEE_FIXTURE_IMAGE` builds
the stack on the host instead, which fetches and builds several GB on its
first run.

## What it does not do

- A `RootUnsealer`: the `KeyProtector` serves `ModePerOperation` only, and no
  key is kept in the secure world for go-enclave beyond the TA's sealing key.
- `Importer`, `Sweeper`, `Attester` or `Confiner`.
- Run on any platform but Linux: elsewhere `Connect` returns a
  `*PlatformError` before any I/O.
- Run conformance on a hardware board in CI. CI runs OP-TEE on QEMU `virt`.

## References

- GlobalPlatform, *TEE Client API Specification* v1.0 (GPD_SPE_007):
  <https://globalplatform.org/specs-library/tee-client-api-specification/>.
  Its licence forbids a copy; it is referenced by title and URL only.
- RFC 9562, *Universally Unique IDentifiers (UUIDs)*: the TA's UUID (version
  4) and its byte layout in `TEEC_UUID`
  ([copy](../reference/rfc9562.txt)).
- Linux, `include/uapi/linux/tee.h`: the TEE subsystem's ioctl interface, at
  the kernel the fixture pins ([copy](../reference/linux-uapi-tee.h)).

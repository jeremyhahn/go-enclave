# arm-trustzone backend — design

> **Status: NORMATIVE** · Scope: go-enclave; trusted-firmware (secure world) · Last verified: 2026-10-31
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it. Slices 2 (the backend) and 3 (the harness and the CI job) are shipped.
> The design of the out-of-tree backend that reaches OP-TEE through the [backend seam](architecture.md). Its harness is [backend-conformance](../backend-conformance/engineering.md#the-arm-trustzone-harness); the secure world and the TA are trusted-firmware's at `v0.4.2-alpha`. All three decisions are ruled: 1 and 2 (A), 3 (B).

This is the design of the `arm-trustzone` backend ([SPEC](../SPEC.md), #206).
Ruling 176434 (#254) took recommendation (A) for decisions 1 and 2, and slice
2 ships them: the nested module `backends/armtrustzone`, pure Go over
`/dev/tee0` ([user](user.md#arm-trustzone), [engineering](engineering.md#arm-trustzone)).
Ruling 274(9) took (B) for decision 3, where the fixture runs. Slice 3 ships
the CI job, which pulls the fixture image by its pinned ghcr digest.

## Problem

go-enclave's [backend seam](architecture.md) has no backend that
reaches a Trusted Execution Environment on Arm. The `arm-trustzone` row
delivers one: an [out-of-tree backend](architecture.md#an-out-of-tree-backend)
that opens a session with a Trusted Application (TA) in OP-TEE and fills a
memory enclave handle with random bytes the secure world produced, run by
`backendtest` against OP-TEE on QEMU `virt`.

The row fixes the seam `backendtest` assumes ([SPEC](../SPEC.md)):

- `Connect(endpoint string) (enclave.Backend, error)`;
- `Random(ctx, n) (enclave.Handle, error)`;
- the backend supplies `test/integration/enclave/arm_trustzone_register_test.go`
  under the `optee` tag.

## Boundaries

| Owner | Holds | Source |
|---|---|---|
| go-enclave, root module | the backend seam and the detection that finds a backend | [backends/](architecture.md) |
| go-enclave | `backendtest` and the arm-trustzone harness, including `make integration-test-arm-trustzone` | [The arm-trustzone harness](../backend-conformance/engineering.md#the-arm-trustzone-harness) |
| go-enclave, the nested module `backends/armtrustzone` | the backend itself: the Go side of the TEE Client API, `Connect`, `Random` and its conformance test | [Decision 1](#decision-1-where-the-backend-lives-ruled-a) |
| trusted-firmware, tag `v0.4.2-alpha` (e0ae83d06) | the secure world (TF-A at EL3, OP-TEE OS 4.11.0 at S-EL1), the TA at S-EL0, the fixture `make optee-run` | trusted-firmware row `optee-trustzone`, trusted-firmware#253 |

The root module stays interface-only (#187): a backend depends on go-enclave,
never the reverse, and the root module keeps its one dependency,
`golang.org/x/sys`.

The fixture boots the stack headless on QEMU `virt` (Armv8-A), with Linux in
the normal world running the TEE driver (`/dev/tee0`) and `tee-supplicant`.
The GP TEE Internal Core API inside is version 1.3.1. `make optee-run` mounts
the host directory `OPTEE_SHARE` in the guest at `/mnt/host` and exits with
the status of `OPTEE_GUEST_CMD`; those two variables are an interface that
extends and does not change meaning.

## The TA interface

As trusted-firmware's tag fixes it in `optee/ta/include/tfw_ta.h`:

| Item | Value | Parameters |
|---|---|---|
| UUID | `23751b49-3a76-4e49-b63c-e5853742fa1f` (RFC 9562, version 4) | – |
| `TFW_TA_CMD_GET_INFO` | `0x00000001` | param 0 `VALUE_OUTPUT`: `a` the interface version, `b` the flags |
| `TFW_TA_CMD_GET_RANDOM` | `0x00000002` | param 0 `MEMREF_OUTPUT`: 1 to 4096 bytes |
| `TFW_TA_CMD_SEAL` | `0x00000003` | param 0 `MEMREF_INPUT`: plaintext; param 1 `MEMREF_INPUT`: associated data, may be empty; param 2 `MEMREF_OUTPUT`: the sealed blob |
| `TFW_TA_CMD_UNSEAL` | `0x00000004` | param 0 `MEMREF_INPUT`: the sealed blob; param 1 `MEMREF_INPUT`: associated data; param 2 `MEMREF_OUTPUT`: the plaintext |
| `TFW_TA_INTERFACE_VERSION` | `1` | – |
| `TFW_TA_INFO_FLAGS` | `0` | – |
| `TFW_TA_RANDOM_MIN` / `_MAX` | `1` / `4096` | – |

SEAL and UNSEAL return `TEE_ERROR_SHORT_BUFFER` (`0xFFFF0010`) with the size
they needed in param 2's size; UNSEAL returns `TEE_ERROR_MAC_INVALID`
(`0xFFFF3071`) for a tampered blob. The backend calls them through its
[`KeyProtector`](#keyprotector); the TA side is trusted-firmware's, and a
pinned TA that predates it answers SEAL as it answers any command it does not
define.

A `Random(ctx, n)` with `n` above 4096 is served in chunks of at most 4096
bytes, each written straight into the handle; `n` of 0 is refused before the
TA is called.

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
  or above the buffer, is a `CommandError` (`ErrCommandFailed`).
- **UNSEAL's output.** When the driver registers the key's pages, the TA
  writes into the caller's `key` directly; otherwise the plaintext lands in
  driver shared memory, is copied into `key`, and the shared memory is wiped.
- **Error mapping.** On UNSEAL, `TEE_ERROR_MAC_INVALID`,
  `TEE_ERROR_BAD_FORMAT` (`0xFFFF0005`), `TEE_ERROR_SHORT_BUFFER` and a
  plaintext of a length other than `len(key)` all match
  `enclave.ErrSealedAuthentication`, as do an empty blob, a blob above 4096
  bytes and an empty `key`, which are refused before the TA is called. Any
  other result, `TEE_ERROR_BAD_PARAMETERS` among them, is a `CommandError`;
  driver failures are a `DeviceError`, and a closed backend is
  `ErrBackendClosed`. `key` is zeroed on every failure.

It meets the [provider contract](../sealing/engineering.md#provider-contract):
UNSEAL authenticates every blob (§1); `Unprotect` writes exactly `len(key)`
bytes into the caller's `key` (§2); `Protect` keeps no key, and its copy in
driver shared memory is wiped (§3); the blob is copied, never kept or changed
(§4); an ended context is refused before the TA is called, and one ending
during the call cancels it (§5); infrastructure failures are the backend's own
errors (§6); concurrent calls are serialized by the session lock (§7); and
`Health` returns nil without blocking (§8).
`TestKeyProtectorConformance_OnOPTEE` runs `providertest.TestProvider`
against it on the fixture.

The sealing transport is also tested without the fixture. The client reaches
the kernel through a small driver seam (open, ioctl, shared-memory register,
mmap, munmap, close), and an ordinary `go test` replaces it with a fake TEE
driver whose TA seals with AES-GCM. The fake runs the provider suite, the
param wiring of SEAL and UNSEAL, the short-buffer retry, tampered blobs and
cancels. It runs each of these with registered memory and with driver shared
memory, and fails if any shared memory or session outlives the call. On the
fixture, GET_INFO cannot decide whether the TA has SEAL: trusted-firmware's TA
reports interface version 1 and flags 0 with SEAL and without it, and no
error code proves SEAL absent, since a TA with SEAL can answer
`TEE_ERROR_BAD_PARAMETERS` to a broken SEAL call and to an unknown command
alike. The fixture therefore declares it: `GO_ENCLAVE_OPTEE_SEAL` left empty,
`scripts/optee-fixture.sh` passes `absent:<TRUSTED_FIRMWARE_TAG>`, and the test
skips on SEAL's `TEE_ERROR_BAD_PARAMETERS` or `TEE_ERROR_NOT_SUPPORTED` only
when that release is `opteeSealAbsentRelease`
(`backends/armtrustzone/sealdecision_linux_test.go`), the pinned release known
to lack SEAL; a new pin without SEAL raises both. With the knob empty in the
test, or `required`, any SEAL error fails it; a SEAL that works runs the
suite under every value. `GO_ENCLAVE_OPTEE_SEAL=required`, passed through
`integration-test-arm-trustzone`, turns the fixture's skip into a failure; CI
leaves it unset. The fake TEE runs this decision (`TestSealDecision`).

## Data flow

1. The conformance test is built as a static `linux/arm64` binary (the
   `optee` tag composes `arm_trustzone_register_test.go`) and dropped into
   `OPTEE_SHARE`.
2. `OPTEE_GUEST_CMD` runs it in the guest from `/mnt/host`, with
   `GO_ENCLAVE_OPTEE_ENDPOINT=/dev/tee0`. The harness that does this is
   merged: [The arm-trustzone harness](../backend-conformance/engineering.md#the-arm-trustzone-harness)
   and the `integration-test-arm-trustzone` target in the
   [Makefile](../../Makefile).
3. `Connect(endpoint)` opens the device, initialises a TEE context and opens
   a session with the TA by its UUID. A missing device, a missing TA or a
   refused session is a typed error.
4. `GET_INFO` is the `CapabilityProbe`: the backend accepts interface version
   1 with flags 0 and refuses anything else with a typed error, so a newer TA
   is never driven by an older client.
5. `Random(ctx, n)` allocates a memory enclave handle of `n` bytes and fills
   it through `GET_RANDOM`.

### Trust boundary

The random bytes cross a buffer shared between the secure world and the
normal world: the `MEMREF_OUTPUT` parameter. Whatever the TA holds in the
secure world before it writes that buffer is trusted-firmware's to wipe.

On the go-enclave side the proposal is:

- Where the kernel accepts registered memory (`TEE_IOC_SHM_REGISTER`), the
  shared buffer *is* the handle's locked, guarded pages: the TA writes into
  them, there is no copy, and the handle's own zeroisation on `Destroy` wipes
  the bytes.
- Otherwise the backend allocates driver shared memory, copies each chunk
  into the handle, and zeroes the shared buffer before it unmaps and
  releases it, on every path, including an error or a cancelled `ctx`.

This slice keeps no key in the secure world. The bytes leave it as soon as
they are produced, and the handle in the normal world is their only holder.

## Decision 1: where the backend lives (ruled: A)

- **(A) A nested module in this repository**, with its own `go.mod` (for
  example `backends/armtrustzone/`) and prefixed tags
  (`backends/armtrustzone/v0.1.0-alpha`). trusted-firmware's `sdk/go/` tags
  are the precedent.
- **(B) A repository of its own.**
- **(C) In the root module.** Rejected: it breaks the interface-only rule
  (#187) and adds platform code to the root.

**Recommendation: (A).** The backend, the seam it implements and the
`backendtest` harness that drives it change together in one pull request and
one CI run, while the root module's `go.mod` stays untouched. The dependency
still runs one way: the nested module requires the root, not the reverse.
(B) adds a repository, a second CI and a cross-repository version bump for
every seam change, with no gain while go-enclave is the backend's only
consumer.

Cost: every release that changes the backend cuts a second, prefixed tag
under the release targets (alpha tags only); a root API change must be
tagged before the nested module can require it; and the buildgates and the
releasability gate learn a second module.

## Decision 2: how the backend reaches the TEE (ruled: A)

- **(A) Pure Go over the Linux TEE subsystem's ioctl interface** on
  `/dev/tee0` (`include/uapi/linux/tee.h`), through `golang.org/x/sys/unix`.
  It implements the GP TEE Client API's semantics (`TEEC_InitializeContext`,
  `TEEC_OpenSession`, `TEEC_InvokeCommand`, the `TEEC_Operation` parameter
  types, `TEEC_UUID`) with `CGO_ENABLED=0`, and builds a static arm64 binary.
- **(B) cgo over OP-TEE's `libteec`.** It needs the guest's arm64 sysroot to
  cross-compile, a cgo toolchain in the image, and dynamic linking in the
  guest.

**Recommendation: (A).** The test binary stays static and drops into
`OPTEE_SHARE` as it is; the image needs no cross C toolchain; the backend
adds no dependency beyond `golang.org/x/sys`; and registered shared memory
(the [trust boundary](#trust-boundary)) is reachable directly.

Cost: go-enclave carries its own client of the ioctl ABI. The struct layout
and the ioctl numbers must be checked against the pinned Linux kernel's
header in the code slice, and a kernel bump re-checks them; `libteec`'s
behaviour (session login methods, parameter encoding, the `TEEC_UUID` byte
order of RFC 9562) is reimplemented rather than inherited.

## Decision 3: where the fixture runs (ruled: B)

Ruling 274(9) chose (B): the one CI job that runs outside the toolchain image,
the `optee` job, runs on an OP-TEE QEMU fixture image that Infra builds and
keeps, on a GitHub-hosted runner (`ubuntu-latest`) with no module credential,
because every module is public. What the job needs of that image is the
[fixture image contract](../backend-conformance/engineering.md#fixture-image-contract).

- **(A) Add trusted-firmware's host packages to go-enclave's toolchain
  image** (`build/docker/devcontainer`), so `make optee-tools` passes in it.
- **(B) Run the CI job in trusted-firmware's `optee` image**, as
  trusted-firmware's own CI does.

A local run caches `OPTEE_CACHE` (outside the checkout) under the key
`make -s optee-pin` prints: its first fixture build fetches and builds
several GB, about 19 minutes on a 24-thread host. The CI job uses the
fixture image's prebuilt stack and never builds it.

**Recommendation: (B).** The package set belongs to the fixture, and
trusted-firmware already maintains an image that carries it; copying it into
go-enclave's toolchain image would grow every other job's image and drift
from the pin. The fixture image is Infra's to build and
keep, so slice 3 uses it rather than building it.

Cost: one CI job runs outside the toolchain image, against the devcontainer
rule for builds, and local runs of the target need that image too.

## What this does not do

- A `RootUnsealer`: the `KeyProtector` serves `ModePerOperation` only, and no
  key is kept in the secure world for go-enclave beyond the TA's sealing key.
- Attestation.
- `Confiner`.
- Any hardware other than QEMU `virt`. Owner queue 41 allows no simulators or
  mocks for hardware backends; OP-TEE on QEMU is the one software-only slice.

## Slices

1. This design. Shipped.
2. The backend and its optee-tagged conformance test, against the ruled
   decisions. Shipped.
3. The `TRUSTED_FIRMWARE_TAG=v0.4.2-alpha` pin, the harness's wiring to the
   conformance test, and the CI job. Shipped by the `optee` CI job and the
   `OPTEE_FIXTURE_IMAGE` pin; the job pulls the image by its pinned digest.

## References

- GlobalPlatform, *TEE Client API Specification* v1.0 (GPD_SPE_007):
  <https://globalplatform.org/specs-library/tee-client-api-specification/>.
  Its licence forbids a copy; it is referenced by title and URL only.
- RFC 9562, *Universally Unique IDentifiers (UUIDs)*: the TA's UUID (version
  4) and its byte layout in `TEEC_UUID`.
- Linux, `include/uapi/linux/tee.h`: the TEE subsystem's ioctl interface, at
  the kernel the fixture pins.

Both are copied into [docs/reference/](../reference/README.md) with their
revisions and implementing symbols.

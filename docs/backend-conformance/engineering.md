# Backend conformance — engineering contract

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-10-14
> Conflicts with this document are defects. For shipped behavior the code is canonical: fix this document to match it.

The suite holds a backend to the contract in
[backends/engineering.md](../backends/engineering.md). Its design is in
[architecture.md](architecture.md).

## Exported surface

| Identifier | Contract |
|---|---|
| `TestBackend(ctx, cfg) error` | Runs every check once against fresh backends. A nil `ctx` is `context.Background()`. Returns nil, or one of the errors below; never panics on a backend's panic. |
| `Config` | The run's input ([fields](#config)). |
| `HandleCase` | One kind of handle the backend makes ([fields](#handlecase)). |
| `ErrInvalidConfig`, `ConfigError{Field, Reason}` | The `Config` cannot be run; no backend was tested. Returned on its own, not inside a `FindingsError`. Text: `backendtest: Config.<Field> <Reason>`. |
| `ErrUncheckedCapability`, `UncheckedCapabilityError{Case, Capability, Reason}` | A declared capability the suite cannot exercise. Returned on its own when the `Config` shows it up front, and inside a `FindingsError` when a check finds it. `Case` is empty for the backend's own capabilities. |
| `ErrNotMeasured`, `NotMeasuredError{Property, Reason}` | A property could not be measured on this host and the `Config` did not accept that. |
| `ErrAborted`, `AbortedError{Cause}` | `ctx` ended before the run finished. Matches `ErrAborted`, unwraps to `Cause` (`context.Canceled`, `context.DeadlineExceeded`). |
| `FindingsError{Findings []error}` | Every finding of the run, in the order found, never empty. `Unwrap() []error` returns them, so `errors.Is` and `errors.As` reach each one. `Error()` prints one finding per line. |
| `ErrNoEndpoint`, `EndpointError{Variable}` | Never returned by `TestBackend`. A harness reports it when the environment variable that names the endpoint it reaches the backend's device through is empty, so no backend was tested ([arm-trustzone harness](#the-arm-trustzone-harness)). Text: `backendtest: no endpoint is set for the backend: $<Variable> is empty`. |
| `ErrNoRegistration`, `RegistrationError{Backend}` | Never returned by `TestBackend`. A harness reports it when no file built into the test binary registers the backend it tests in-process, so no backend was tested ([arm-trustzone harness](#the-arm-trustzone-harness)). Text: `backendtest: no in-process registration of the backend is built in: <Backend>`. |
| `PropertyError{Property, Detail}` | One property of the seam the backend did not honor. Several may share a `Property`. Text: `backendtest: <Property>: <Detail>`. |

### `Config`

| Field | Contract |
|---|---|
| `New func() (enclave.Backend, error)` | Required. Returns a fresh backend; called at most once per check. A nil backend, typed nil included, is a finding. |
| `BackendCapabilities []enclave.Capability` | Exactly what the backend itself claims: `CapabilityImport`, `CapabilitySweep`, `CapabilityConfine`, `CapabilityAttest`, `CapabilityProbe`. |
| `Handles []HandleCase` | Required, at least one. |
| `SkipResidueSweep string` | If set, the reason the residue sweep may not run; the result is a note on `Logf` instead of a `*NotMeasuredError`. |
| `VerifyEvidence func(nonce []byte, evidence enclave.Evidence) error` | Returns nil when the evidence binds `nonce`, an error when it does not, as the attestation's relying party would judge it. Without it every `Attester` the suite meets is an `*UncheckedCapabilityError`: attestation binding is certified only with it. |
| `Logf func(format string, args ...any)` | Receives notes about skipped optional measurements. May be nil. |

### `HandleCase`

| Field | Contract |
|---|---|
| `Name string` | Required, unique among the cases; names the case in every failure. |
| `New func(ctx, b enclave.Backend) (enclave.Handle, error)` | Returns a live handle of `b`, such as a key the device generates. Exactly one of `New` and `Import` is set. |
| `Import []enclave.ImportOption` | For an `Importer`: the option set the suite imports `ImportSize` random bytes with. The case then also checks the purpose's handle contract. |
| `ImportSize int` | Positive for an imported case. |
| `Capabilities []enclave.Capability` | Exactly what this case's handles claim: `CapabilityBytes`, `CapabilityFreeze`, `CapabilitySign`, `CapabilityDecrypt`, `CapabilityAEAD`, `CapabilityDerive`, `CapabilityAttest`. |

## Invariants

1. **Fails closed.** A check that cannot run is a `*NotMeasuredError` or an
   `*UncheckedCapabilityError`, never a pass. `SkipResidueSweep` is the only
   waiver, and it leaves a note on `Logf`.
2. **Typed errors only.** Every error is declared in
   [backendtest/errors.go](../../backendtest/errors.go). A `Config` it refuses
   before any check is a bare `*ConfigError` or `*UncheckedCapabilityError`;
   otherwise the result is nil or a `*FindingsError`.
3. **Only what failed while `ctx` was live is reported.** After it ends a
   compliant backend fails its calls with the context's error, so a later
   failure is the abort, not a finding. A panic is reported either way. No
   further check starts once `ctx` ends.
4. **A fresh backend per check.** Every check that needs a backend calls
   `Config.New` afresh.
5. **No import of `testing`, no new dependency**, and nothing in the root
   package depends on `backendtest`.
6. **The suite wipes what it holds.** It wipes the random material it imports
   and the buffer its residue sweep scans.

## Error semantics

| Error | From | Matches |
|---|---|---|
| `*ConfigError` | `TestBackend`, before any check | `ErrInvalidConfig`; `Field` is the field at fault (`New`, `Handles`, `Handles[i]` for a case setting both or neither of `New` and `Import`, `Handles[i].Name`, `Handles[i].ImportSize`, `Handles[i].Capabilities`, `BackendCapabilities`). |
| `*UncheckedCapabilityError` | `TestBackend`, before any check or from a check | `ErrUncheckedCapability`. |
| `*FindingsError` | `TestBackend` | Itself; unwraps to each finding. |
| `*PropertyError` | A check | Itself, by `errors.As`; `Property` is the bold name in [What it checks](#what-it-checks). |
| `*NotMeasuredError` | The residue check | `ErrNotMeasured`. |
| `*AbortedError` | `TestBackend`, last | `ErrAborted` and the context's error. |

Match with `errors.Is` and `errors.As`, never the text.

## What it checks

Each bold name is the `Property` of the `*PropertyError` the check reports.
A check that panics is reported as **panic safety**, including a panic in one
of the concurrent-use goroutines.

1. **Configuration**, before any check. `New` is set; `Handles` is not
   empty; case names are non-empty and unique; each case sets exactly one of
   `New` and `Import`, and an imported case a positive `ImportSize`; no
   capability list repeats a capability or holds one from the other side of
   the seam. Each of these is a `*ConfigError`. A capability the enclave
   package does not name, `CapabilityFreeze` without `CapabilityBytes`, and
   `CapabilityImport` with no imported case (no valid import would ever be
   seen to succeed) are refused as unchecked.
2. **Backend identity.** `Config.New` returns a non-nil backend without error,
   and `Name` is a valid backend name and stable.
3. **Backend capabilities are exact** and **handle capabilities are exact**:
   each capability the backend or a case claims is found by type assertion on
   the backend or on that case's handle, and each unclaimed one is not.
4. **Handle lifecycle**, for every case. Making the handle succeeds (an
   imported case needs a backend that is an `Importer`) and returns a non-nil
   handle whose dynamic type is a pointer. `Backend()` is non-nil and is the
   backend under test (by `As`), before and after `Destroy`. A new handle is
   alive with a positive `Size`, and an imported one is the material's size.
   After `Destroy` twice, `IsAlive` is false and `Size` is 0. Only a nil
   return obliges the handle to be dead: a `Destroy` that returns
   `ErrLockedMemoryUnavailable`, which the seam documents as resumed by a
   retry, is called again, up to four calls in all, and any other error, or that
   one on every attempt, is a failure; so is an error that leaves the handle
   alive. The same rule judges every `Destroy` the suite calls. Every
   error-returning method the handle has then returns `ErrEnclaveDestroyed`:
   `WithBytes` (without calling fn), `EqualTo`, `Freeze`, `Derive` (with no
   handle), `Sign`, `Decrypt`, `Seal`, `Open` and `Attest`. `NonceSize`,
   `Overhead` and `Public()` are unchanged. No nil receiver is manufactured.
5. **Per capability**, on a fresh live handle of every case that claims it,
   or on the backend for a backend capability:
   - **ByteAccess**: the view is `Size` bytes and holds the imported
     material; `WithBytes` returns fn's error; `EqualTo` is true for the
     material and false for an altered byte or a wrong length.
   - **Freezer**: `Freeze` succeeds and is idempotent, the handle stays alive
     with its material, and a write to the `WithBytes` view faults on every
     page and on its first and last byte, each probed on its own. A refused
     `Freeze` leaves the handle alive.
   - **Deriver**: an ended context is refused with an error matching its own,
     and no handle. Each derived handle is alive, of the requested size and
     of the parent's backend, and is destroyed cleanly. The same info derives
     the same material and different info different material, compared
     through `ByteAccess` or, failing that, by one `AEAD` opening what the
     other sealed. If either comparison cannot be made that way, the
     capability is refused as unchecked.
   - **crypto.Signer**: signatures verify against `Public()`: ECDSA over
     SHA-256; RSA PKCS #1 v1.5 and PSS over SHA-256; Ed25519. Any other
     public key is refused as unchecked.
   - **crypto.Decrypter**: an RSA-OAEP SHA-256 ciphertext to `Public()`
     decrypts to the message, and a tampered one is refused. A non-RSA public
     key is refused as unchecked.
   - **AEAD**: `Seal` appends to dst and adds at most `Overhead` bytes;
     `Open` appends the plaintext to dst; a wrong-length nonce is
     `ErrInvalidNonce` for both; a flipped bit or different additional data
     is `ErrAEADAuthentication` with no plaintext.
   - **Attester**, on the backend or a case: the evidence has a `Format` and
     `Data`, and differs for different nonces; 1- and 64-byte nonces are
     accepted, an empty or 65-byte nonce is refused, never truncated; an
     ended context is refused with an error matching its own. Evidence for a
     nonce passes `Config.VerifyEvidence` against that nonce and fails it
     against another; with no `VerifyEvidence` the capability is refused as
     unchecked, because evidence that merely differs between calls need not
     bind the nonce.
   - **Importer**: the source is wiped on success, on invalid options (a nil
     option, a wrong AES-256-GCM key length; both `ErrInvalidImport`) and on
     an ended context (an error matching its own). None of these refusals
     returns a live handle; the seam does not require the handle to be nil,
     so a dead one passes, and any handle a refusal returns is destroyed. An
     imported case's handle meets its purpose's contract: its `Size` is the
     material's; a `PurposeMaterial` handle has `ByteAccess`, any other has
     `ByteAccess` or `AEAD`; `ByteAccess` holds the material; an AES-256-GCM
     `AEAD` reports `Overhead` 16 and `NonceSize` 12 (or 0) and, at 12, opens
     what an in-process GCM sealed with the imported key. An `AEAD` handle
     without `ByteAccess` that is not such a key, so the suite cannot see its
     material, is refused as unchecked.
   - **Sweeper**: under a nil and an ended `ctx`, with one handle of every
     case live, `Sweep` returns 0 and nil, every handle is destroyed as item 4
     requires (`IsAlive`, `Size` and every error-returning method), and a
     second `Sweep` returns 0 and nil again.
   - **Confiner**: `ConfinesProcess` gives the same answer every time.
   - **Prober**: `Rank` gives the same answer every time, and `Probe` gives
     one verdict, nil or an error, under the run context and a nil one,
     called again and from 32 goroutines at once, without panicking. Whether
     the verdict matches the host is the backend's own test.
6. **Concurrent use**, for every case. 32 goroutines, released together from
   a start barrier, run every operation the handle has, `Size`, `IsAlive`,
   `Backend` and, on a `Freezer`, `Freeze` included, while `Destroy` lands,
   and each again after it returns. `Destroy` is called once an operation is
   under way: with `ByteAccess`, one `WithBytes` borrow is held open from the
   `Destroy` call until `Destroy` returns, for at most 20 ms, and a `Destroy`
   that returns while that borrow is still open is a failure: `Destroy` waits
   out in-flight borrows. Destroy is judged by the lifecycle rule above, no
   operation returns an error other than `ErrEnclaveDestroyed`, `Size` is the
   live size or 0, `Backend` is the backend under test, and no borrow sees
   bytes other than the material, such as wiped or freed memory. Once
   `Destroy` has returned nil, each goroutine's last pass checks the destroyed
   state of item 4, `IsAlive`, `Size` and `Backend` apart from the
   error-returning methods. Run it under `-race`.
7. **Residue** (Linux, [internal/memscan](../../internal/memscan/memscan_linux.go)),
   for every case that claims `ByteAccess`. A locked copy of the material is
   the needle. A control sweep with the handle alive must find the material
   outside the needle. After `Destroy`, a second sweep must find it nowhere. A
   backend that claims `CapabilitySweep` is measured again on a fresh handle
   ended by `Sweep` instead of `Destroy`. If the platform has no sweep, the
   control misses, the sweep fails, or the material is under 16 bytes, the
   result is a `*NotMeasuredError`. `SkipResidueSweep` turns this into a note
   logged through `Logf`.

## FIPS 140-only toolchains

The AES-256-GCM check in item 5 (**Importer**) builds an in-process
`cipher.NewGCM` from the imported key and seals with a nonce the suite
supplies, to prove the handle holds that key. Under a toolchain that enforces
FIPS 140 mode (`GODEBUG=fips140=only`), `cipher.NewGCM` refuses
caller-supplied nonces, so the suite builds the comparison itself: it seals
through the handle and checks the ciphertext body against the imported key's
AES-CTR keystream from GCM's second counter block (J0+1, counter value 2). That still proves the handle
holds the imported key, and nothing panics, so the suite runs as it does without
`fips140=only`. A handle that draws its own nonce (`NonceSize` 0) skips the
comparison and has its constants checked only.

## Cost

Linear in the number of cases: each case builds a handful of handles per
check, plus 32 goroutines for the concurrency check and one scan of the
process's readable mappings per residue measurement. The concurrency check
holds one borrow open for at most 20 ms per case.

## Configuration and persistence

None beyond `Config`. The suite persists nothing.

## Test strategy

`backendtest/backendtest_test.go` runs the suite against the `Allocator` (the
locked-memory backend) and against well-behaved fakes, and drives the invalid
config, unchecked capability, aborted run and residue paths.
`backendtest/fake_test.go` holds a deliberately broken fake for each check, and
the check must catch it;
`errors_test.go` covers each error's text, sentinel and unwrapping.
`frozenhead_unix_test.go` and `frozenhead_windows_test.go` are the
per-platform probes of a frozen mapping's first page. `make test-backend-conformance` (the `backendtest` package's `make test-backendtest`)
runs them and `make coverage-backendtest` holds the package to the coverage
floor. `make integration-test-backend-conformance` selects the integration
tests named `TestBackendConformance_` in
`test/integration/enclave/backend_conformance_test.go`: the `Allocator`
passes, a backend that under-claims a capability is a finding, and an invalid
config is refused.

### The arm-trustzone harness

`make integration-test-arm-trustzone` runs the arm-trustzone conformance tests,
`TestBackendConformance_OnOPTEE` and `TestKeyProtectorConformance_OnOPTEE` in
`backends/armtrustzone/conformance_optee_test.go`, against the backend on
OP-TEE ([#250](../../../../issues/250), [#206](../../../../issues/206)). The
backend and its design are in
[arm-trustzone-design.md](../backends/arm-trustzone-design.md). The tests are
built only with the `optee` tag, so no other run compiles them,
`make integration-test-backend-conformance` included. The target compiles
`backends/armtrustzone` with `go test -c -tags=optee` as a static linux/arm64
test binary (`CGO_ENABLED=0`) in the toolchain image (`scripts/devcontainer.sh
run`, as `make docker-run` does) into the checkout's ignored
`bin/optee/armtrustzone.test`. `scripts/optee-fixture.sh harness` then copies
it into a fresh share directory and runs the pinned checkout's
`make optee-run OPTEE_SHARE=<dir> OPTEE_GUEST_CMD=<binary>` on the host, the
only step that runs there. The guest runs `TestBackendConformance_OnOPTEE`
and `TestKeyProtectorConformance_OnOPTEE` with `GO_ENCLAVE_OPTEE_ENDPOINT` set (default `/dev/tee0`, the guest's TEE
device), and `optee-run`'s status, the binary's, is the target's. It refuses
while `TRUSTED_FIRMWARE_TAG` is empty, and the script refuses a missing
binary.

- **Fixture.** trusted-firmware's `make optee-run`: an aarch64 QEMU virt
  guest (qemu_v8) with the OP-TEE trusted application, which mounts
  `OPTEE_SHARE` at `/mnt/host` and runs `OPTEE_GUEST_CMD` there. It is a CI
  test fixture, not a Go import: `golang.org/x/sys` stays go-enclave's only
  dependency. It is another process from the registry's point of view, so it
  cannot register anything in the test binary's registry.
- **Pin.** `scripts/tool-pins.sh` pins `TRUSTED_FIRMWARE_TAG=v0.4.2-alpha`
  and `TRUSTED_FIRMWARE_COMMIT`, the commit the annotated tag peels to
  (`e0ae83d062b4…`). The clone URL is the forge's, so the caller supplies it
  as `TRUSTED_FIRMWARE_URL` (empty refuses); the commit, not the URL, is what
  is trusted. The script clones the tag into `TRUSTED_FIRMWARE_CACHE/<tag>` (default
  `~/.cache/go-enclave/trusted-firmware`, outside the tree, one directory per
  tag) and refuses, with one line and a non-zero exit, a checkout whose
  `HEAD` is not `TRUSTED_FIRMWARE_COMMIT` or whose tracked files are
  modified: a moved tag is refused, never followed. The pin moves by an
  ordinary PR that raises the tag and its commit together; a command-line
  `TRUSTED_FIRMWARE_TAG` without its commit is refused the same way.
- **Fixture check.** `make optee-fixture-check` (body:
  `scripts/optee-fixture.sh check`) runs the pinned checkout's
  `make integration-test-optee`: xtest, then the TA's version and rng
  commands. It proves the fixture boots and the TA answers, with no
  go-enclave code involved.
- **Host.** Both targets run where QEMU runs, not in the devcontainer. One
  fixture build is several GB and tens of minutes, cached by trusted-firmware
  in its `OPTEE_CACHE` (default `~/.cache/trusted-firmware/optee`, one
  directory per pin). It needs Python 3 with cryptography and pyelftools,
  ninja, meson, glib, pixman and the OpenSSL headers; trusted-firmware
  refuses with every missing package before it fetches anything. The share
  path may hold no comma or space (`optee-run` refuses it), so set `TMPDIR`
  if yours does.
- **CI.** The `optee` job in `.github/workflows/ci.yml` runs
  `make integration-test-arm-trustzone OPTEE_FIXTURE_IMAGE=<pin>` on the
  GitHub-hosted runner `ubuntu-latest` with no module credential, because
  every module is public (ruling 274(9)), full tier and every nightly, when the
  changes job's `optee` output is true: a change under
  `backends/armtrustzone/`, to `scripts/optee-fixture.sh`, to
  `test/integration/enclave/main_optee_test.go`, or to a `TRUSTED_FIRMWARE_*`
  or `OPTEE_FIXTURE_IMAGE` pin. The test binary is compiled in the toolchain
  image as above; `scripts/optee-fixture.sh harness` then runs in the fixture
  image (the [contract](#fixture-image-contract)) with
  `OPTEE_FIXTURE_PREBUILT=1`, which uses the image's checkout and refuses to
  clone, so the job never builds the stack (about 155 min cold). The commit
  check applies to that checkout as to a clone. `OPTEE_FIXTURE_IMAGE` in
  `scripts/tool-pins.sh` is empty until Infra publishes the image, and the
  job fails while it is empty, never skips.
- **Registration.** The registry is per process. The test registers the
  backend in its own binary with `enclave.Register(Connector{})` and finds it
  with `enclave.Lookup`. The root's optee-tagged harness,
  `test/integration/enclave/arm_trustzone_test.go`, is not run by the target:
  the root `go.mod` never requires the nested module, so nothing can register
  the backend in that binary, and its conformance test can only refuse with a
  `*backendtest.RegistrationError` (`ErrNoRegistration`).
- **What it asks of the backend.** The registered backend has
  `Connect(endpoint string) (enclave.Backend, error)`, and `Config.New` calls it
  for a fresh backend per check. The connected backend claims
  `CapabilityProbe`, behind the TA's version command (0x1). Its one handle case,
  `rng`, is `Random(ctx, 32)`: a `CapabilityBytes` handle filled by the TA's
  rng command (0x2). Commands 0x3 and 0x4 (SEAL and UNSEAL) are named by the
  `keyprotector-providers` SPEC row: `TestKeyProtectorConformance_OnOPTEE`
  runs the provider suite (`providertest.TestProvider`, `ModePerOperation`)
  against `(*Backend).KeyProtector()` on the same fixture. It skips, naming
  trusted-firmware's SEAL as not yet in the pinned TA, only when SEAL answers
  `TEE_ERROR_NOT_SUPPORTED` or `TEE_ERROR_BAD_PARAMETERS`.
- **Fails, never skips.** An empty `GO_ENCLAVE_OPTEE_ENDPOINT` is a
  `*backendtest.EndpointError` (`ErrNoEndpoint`). A failed registration or
  lookup, or a backend without `Connect`, fails the test. A skipped run would
  look like a pass. The `KeyProtector` test's one skip, above, is for a TA
  without SEAL; every other failure of it fails.

### Fixture image contract

`OPTEE_FIXTURE_IMAGE` is the OP-TEE fixture image (ruling 274(9)), published
to `ghcr.io/jeremyhahn/go-enclave-optee-fixture` by the repository's
`ghcr-optee-fixture.yml` workflow and pinned in `scripts/tool-pins.sh` by its
manifest digest (`ghcr.io/<owner>/<name>@sha256:<64 hex>`). The package is
public, so the GitHub-hosted optee job pulls it with no login or secret. The
image is raised with the trusted-firmware pins by re-running that workflow and
pinning the digest it prints. The optee job runs it with `docker run`,
the repository mounted read-only at `/src` as the working directory, and
`sh scripts/optee-fixture.sh harness` as the command, as the image's default
user. The image holds:

- **The checkout.** trusted-firmware cloned at `TRUSTED_FIRMWARE_TAG`, its
  `HEAD` at `TRUSTED_FIRMWARE_COMMIT` (both pinned in `scripts/tool-pins.sh`),
  at `/opt/go-enclave/trusted-firmware/<tag>` (the job's
  `TRUSTED_FIRMWARE_CACHE`, `OPTEE_FIXTURE_CACHE` in the Makefile), with a
  `.git` directory, no modified tracked files, and owned by the image's user,
  so `git rev-parse` and `git status` run there.
- **The built stack.** QEMU (`qemu-system-aarch64`, virt machine), TF-A,
  OP-TEE OS 4.11.0 and the Linux guest, built by that checkout into its
  `OPTEE_CACHE` (the default for the image's user, or `OPTEE_CACHE` set in
  the image's environment), so `make optee-run` boots without building.
- **tee-supplicant** in the guest, started at boot, with `/dev/tee0`
  present.
- **The tfw TA**, UUID `23751b49-3a76-4e49-b63c-e5853742fa1f`, built from
  the checkout and installed where the guest's tee-supplicant loads it.
- **The tools `make optee-run` needs:** `sh`, `git`, GNU `make`, `mktemp`,
  and the [host](#the-arm-trustzone-harness) packages trusted-firmware checks
  for (Python 3 with cryptography and pyelftools, ninja, meson, glib, pixman,
  the OpenSSL headers), with a `TMPDIR` whose path holds no comma or space.

A new trusted-firmware pin needs a new image: the image and the
`TRUSTED_FIRMWARE_*` pins move in one PR.

The image unpacks to 27.4 GB, more than a GitHub-hosted runner has free, so
the optee job frees disk, moves Docker's data root to the runner's `/mnt`
filesystem, and fails before the first pull when that root has less than the
job's `NEED_GB` free.

## Observability

`Config.Logf` receives a note for each measurement the config allowed to be
skipped. Log the result of `TestBackend` with `t.Fatal(err)`: `FindingsError`
prints one finding per line.

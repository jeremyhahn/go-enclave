# Integration coverage by feature

> **Status: REFERENCE** · Scope: go-enclave · Last verified: 2026-11-12
> For shipped behavior the tests are canonical: fix this document to match them.

Which integration tests exercise each feature in [docs/](../../docs/README.md).
The root module has one integration suite, `test/integration/enclave/`. It runs
only in the project devcontainer (`make integration-test-enclave`, and
`make integration-test-fips-enclave` for FIPS 140-3 strict mode), and is gated
at `COVERAGE_THRESHOLD` on the root package and on `providertest`, each on its
own. Each case needs what a unit test
cannot have: the real kernel's `RLIMIT_MEMLOCK`, VmLck and VmFlags, a full
`/proc/self/mem` sweep, a seccomp fault injector, or a process-wide limit set
in a fresh child process. Everything else is a unit test in the package itself.
The nested backend modules run their conformance tests against device
fixtures instead ([below](#backend-module-fixtures)).

Every test is named for the one feature it belongs to, with the prefix
[scripts/features.map](../../scripts/features.map) gives that feature
(`TestMemoryEnclave_`, `TestLockedMemoryBudget_`, `TestSealing_`,
`TestShutdownSweep_`, `TestBackends_`, `TestBackendDetection_`,
`TestBackendConformance_`, `TestLinuxSecretmem_`,
`TestProviderConformance_`). `make integration-test-<feature>` runs the tests
with that prefix and nothing else, and `build/ci/buildgates` fails on a test
with no feature's prefix. A test that serves two features (the table below
lists some) carries the prefix of the one it is mostly about.

The root package's user-namespace test is not in this suite: it needs
`package enclave` internals and a seccomp profile that permits `CLONE_NEWUSER`.
`make integration-test-userns` runs it in its own compose service, as part of
every `integration-test-enclave` and of
`integration-test-locked-memory-budget`.

`providertest` has no suite of its own: its devcontainer cases are in the
enclave suite (provider-conformance below), which gates its coverage at
`COVERAGE_THRESHOLD` alongside the root package's. The unit
`make coverage-providertest` gates it separately.

| Feature | `enclave` suite |
|---|---|
| [memory-enclave](../../docs/memory-enclave/user.md) | `enclave_test.go`: material lives only in its enclave and is gone after `Destroy`; destroyed and nil enclaves refuse every access; accessors and error rendering. `mapping_test.go`: mappings are locked, undumpable and guarded (smaps VmFlags); importing the package leaves the core-dump limit unchanged, and `CoreDumpsDisabled` reports `ErrCoreDumpLimitNotApplied` until `HardenProcess` runs; refused `mlock`, `munmap`, `mprotect`, guard page and exclusion each fail closed. `harden_test.go`: the kernel reports the process not dumpable; a refused `prctl` is reported; a refused `RLIMIT_CORE` change is a `*CoreDumpLimitError` inside the `*ProcessHardeningError`, with the report and `CoreDumpsDisabled` agreeing. |
| [locked-memory-budget](../../docs/locked-memory-budget/user.md) | `allocator_test.go`: admission under the real ceiling, alone and under contention, VmLck cross-checked; the process allocator defaults to the kernel ceiling; `SetAllocator` is one-shot; a zero ceiling fails closed; `ForceLimit` reports its excess; invalid arguments and a nil allocator are refused. `memlock_test.go`: limit sources render. `sealed_test.go`: `OpenIn` admits against the budget. |
| [sealing](../../docs/sealing/user.md) | `sealed_test.go`: no plaintext in the process between opens; destroyed and nil sealed values. `sealer_test.go`: round trips in both modes, contexts reach the provider, root unseal is serialized and abandonable, KEK rotation in real locked memory, running out of locked memory mid-hierarchy, a refused freeze, sweeps overlapping sealer use, configuration and misconfiguration. `sealer_lifecycle_test.go`, `sealer_lifecycle_linux_test.go`: destroyed sealers return their locked memory, an injected provider stays its owner's, destroy during a blocked unseal, a refused release is reported and retried. `enclave_test.go`: key-schedule erasure reports this build. `provider_test.go`: the software provider refuses misuse. `sealing_backend_test.go`: a sealer whose key hierarchy lives in a fake device backend (AEAD keys, with and without an inline nonce) rotates and reclaims generations, refuses an unusable key handle, reports each device failure with its typed error, loses or abandons a rotation race cleanly, and returns its budget to an `*Allocator` backend; `SealFrom` and `NewSealedFrom` seal a frozen enclave in place and refuse what they cannot read; `WithBackend`, `OpenIn` into an importer and `WithRequireKeyScheduleErasure` each accept and refuse; a failure that ended the context reports the sentinel, the context error, its cause and the provider's error. |
| [shutdown-sweep](../../docs/shutdown-sweep/user.md) | `registry_test.go`: `WipeAll` reclaims everything and leaves no residue; waits for live borrows until its deadline; turns away a concurrent caller; reports canary corruption without panicking; reclaims an orphan a refused cleanup left; `SweepError` renders. `backend_sweep_test.go`: `WipeAll` sweeps each registered `Sweeper` in name order, sums what they still hold and reports the failed ones in `SweepError.Backends` (reachable with `errors.Is` and `errors.As`, without the counters' sentinels); a hand-built `SweepError` renders and unwraps; a backend sweep holds the sweep slot against a nil or ended caller. `sealer_test.go`: a sealer is wiped for good after a sweep. |
| [provider-conformance](../../docs/provider-conformance/user.md) | `provider_test.go`: `SoftwareProvider` passes `TestProvider` in both modes with the residue sweep running, and an under-claimed mode list fails; in a child with `RLIMIT_MEMLOCK` at zero the sweep cannot run, and `TestProvider` reports `ErrNotMeasured` unless `SkipResidueSweep` accepts it. `provider_failure_test.go`: `TestProvider` run against a provider broken in one way at a time reports that property as a `PropertyError` and nothing else: a Protect or Unprotect that fails, writes the wrong bytes, keeps the caller's slice or an old destination, accepts a forged blob or a destination of the wrong length, ignores an ended context, shares state across concurrent calls, or keeps a heap copy of the key for the residue sweep; a RootUnsealer that fails, writes a placeholder or half a root, or retains its destinations; a bare public-key wrap that opens a blob built with `Config.Forge`; claimed modes the provider does not serve. An ended run context, or a provider call that never returns, gives `ErrAborted` with no findings; too little locked memory gives `ErrNotMeasured`; each invalid `Config` gives `ErrInvalidConfig` and a `ConfigError` for the field, with no provider built. |
| [backends](../../docs/backends/user.md) | `backend_test.go`: an enclave on the real kernel's locked memory reports the registered default backend, before and after `Destroy`, and `As` reaches its capabilities. `Register` refuses an invalid name, a duplicate, the default's name and a nil or typed-nil backend, each with its typed error, and accepts a valid one that `Lookup` and `BackendNames` then return; `Lookup` reports an unknown name. `As` covers assignable targets, a wrapper's `As` method, nil and typed-nil values and bad targets. `NewImportSpec` with `WithPurpose` and `WithAlgorithm` resolves valid combinations and refuses invalid ones with `ErrInvalidImport`. `backend_allocator_test.go`: an `*Allocator` names the default backend (nil and zero values too) and is the `Backend` of what it admits, before and after `Destroy`; it imports keys and material into its budget, wipes the caller's slice on every path, and refuses an invalid import, an ended context, a spent budget and a nil or unconstructed allocator. |
| [backend-detection](../../docs/backend-detection/user.md) | `detection_test.go`: on a host with nothing else registered, `Detect` selects the default locked-memory backend at rank 0, and a new enclave reports that backend; a registered prober whose device is absent is passed over with a `*ProbeError` that carries the device error and matches `ErrBackendUnavailable`, and a registered backend with no probe is passed over with a `*CapabilityError` for `CapabilityProbe`. `secretmem_test.go` covers selection above locked memory (linux-secretmem below). |
| [backend-conformance](../../docs/backend-conformance/user.md) | `backend_conformance_test.go`: the locked-memory backend (an `*Allocator`) passes `backendtest.TestBackend`; an under-claimed capability list is a `*PropertyError`; an empty `Config` is refused with `ErrInvalidConfig`. |
| [linux-secretmem](../../docs/linux-secretmem/user.md) | `secretmem_test.go`: the secretmem backend passes `backendtest.TestBackend` for material handles with byte access and freeze (its residue sweep is skipped because the kernel refuses `/proc/self/mem` reads of secretmem pages, the property the backend adds); once registered, `Detect` selects it at rank 1 above locked memory and its handles hold the imported material; `Sealed.OpenIn` into it returns a secretmem handle with the sealed material, and a cancelled context fails with `ErrOpenFailed` carrying `context.Canceled`. Each test skips on a kernel without a usable `memfd_secret`. |
| [arm-trustzone](../../docs/backends/user.md#arm-trustzone) | `arm_trustzone_test.go` and `main_optee_test.go`, built only with the `integration` and `optee` tags: a registry-based harness that runs `backendtest` against a backend registered as `arm-trustzone`, and refuses with `*backendtest.EndpointError` when `GO_ENCLAVE_OPTEE_ENDPOINT` is empty and `*backendtest.RegistrationError` when nothing registered the backend. No make target runs it: the root module does not require `backends/armtrustzone`, so nothing in this binary registers the backend. The conformance run on OP-TEE is the module's own ([below](#backend-module-fixtures)). |

## Backend module fixtures

Each nested backend module carries a conformance test behind a build tag,
run against a real device stack rather than the devcontainer.

| Feature | Target | Tests |
|---|---|---|
| [arm-trustzone](../../docs/backends/engineering.md#arm-trustzone), [keyprotector-providers](../../docs/sealing/hardware-providers.md) | `make integration-test-arm-trustzone` | `backends/armtrustzone/conformance_optee_test.go` (`optee` tag), built for linux/arm64 and run in the guest of the pinned OP-TEE fixture ([harness](../../docs/backend-conformance/engineering.md#the-arm-trustzone-harness)). `TestBackendConformance_OnOPTEE` registers the backend in-process and runs `backendtest` with the trusted application's probe and random-filled handles. `TestKeyProtectorConformance_OnOPTEE` runs `providertest` against the backend's `KeyProtector`; it skips only when the fixture declares, through `GO_ENCLAVE_OPTEE_SEAL`, that its pinned trusted-firmware release has no SEAL command, and `GO_ENCLAVE_OPTEE_SEAL=required` turns that skip into a failure. |
| [keyprotector-providers](../../docs/sealing/hardware-providers.md#tpm-provider) | `make integration-test-tpm` | `backends/tpm/conformance_swtpm_test.go` (`swtpm` tag), under `-race` on the host against a throwaway `swtpm`. `TestProviderConformance_OnSWTPM` runs `providertest` with its residue sweep, forging blobs under the unlabelled storage template so the suite measures the label binding; `TestBlobLength_OnSWTPM` checks the sealed blob's length; `TestReclaimAfterInterrupt_OnSWTPM` interrupts each handle-bearing command more times than the TPM has slots and checks every transient handle and session is flushed. |

## Helpers

These files hold no feature tests; each is named for what it provides.

- `main_test.go`: `TestMain`, which refuses to run outside the devcontainer
  (`test/internal/devcontainer`, outside the suites so its unit tests
  carry no feature prefix).
- `procfs_test.go`: the `/proc/self` oracle (status VmLck, smaps VmFlags, and a
  residue sweep that reports every address the material is at).
- `isolation_test.go`: re-runs a test in a fresh child process with its own
  limits.
- `provider_fakes_test.go`: the providers that break one property of the
  provider seam each, wrapped around a real `SoftwareProvider`, and the reading
  of a `TestProvider` verdict by type.
- `seccomp_test.go`: the seccomp fault injector that refuses chosen syscalls,
  and the tests of the injector itself.
- `backend_fakes_test.go`: the backend fakes the sealing, backends and
  shutdown-sweep tests share: a device `Importer` whose keys implement `AEAD`
  and whose faults a test steers, its opaque and phantom handles, a `Confiner`
  and a `Sweeper`.

The `/proc/self/mem` sweep the unit tests and `providertest` share is
`internal/memscan`. `procfs_test.go` keeps its own sweep because it asserts
more: exact addresses, every readable mapping including file-backed ones, a
needle that is never assembled in memory, and failure on any mapping it cannot
read.

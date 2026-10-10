# Integration coverage by feature

Which integration tests exercise each feature in [docs/](../../docs/README.md).
There is one integration suite, `test/integration/enclave/`. It runs only in the
project devcontainer (`make integration-test-enclave`, and
`make integration-test-fips-enclave` for FIPS 140-3 strict mode), and is gated
at `COVERAGE_THRESHOLD` on the root package and on `providertest`, each on its
own. Each case needs what a unit test
cannot have: the real kernel's `RLIMIT_MEMLOCK`, VmLck and VmFlags, a full
`/proc/self/mem` sweep, a seccomp fault injector, or a process-wide limit set
in a fresh child process. Everything else is a unit test in the package itself.

Every test is named for the one feature it belongs to, with the prefix
[scripts/features.map](../../scripts/features.map) gives that feature
(`TestLockedMemory_`, `TestLockedMemoryBudget_`, `TestSealing_`,
`TestShutdownSweep_`, `TestProviderConformance_`, `TestBackends_`). `make
integration-test-<feature>` runs the tests with that prefix and nothing else,
and `build/ci/buildgates` fails on a test with no feature's prefix. A test that
serves two features (the table below lists some) carries the prefix of the one
it is mostly about.

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
| [locked-memory](../../docs/locked-memory/user.md) | `enclave_test.go`: material lives only in its enclave and is gone after `Destroy`; destroyed and nil enclaves refuse every access; accessors and error rendering. `mapping_test.go`: mappings are locked, undumpable and guarded (smaps VmFlags); the core-dump limit is lowered on import; refused `mlock`, `munmap`, `mprotect`, guard page and exclusion each fail closed. `harden_test.go`: the kernel reports the process not dumpable; a refused `prctl` is reported. |
| [locked-memory-budget](../../docs/locked-memory-budget/user.md) | `allocator_test.go`: admission under the real ceiling, alone and under contention, VmLck cross-checked; the process allocator defaults to the kernel ceiling; `SetAllocator` is one-shot; a zero ceiling fails closed; `ForceLimit` reports its excess; invalid arguments and a nil allocator are refused. `memlock_test.go`: limit sources render. `sealed_test.go`: `OpenWith` admits against the budget. |
| [sealing](../../docs/sealing/user.md) | `sealed_test.go`: no plaintext in the process between opens; destroyed and nil sealed values. `sealer_test.go`: round trips in both modes, contexts reach the provider, root unseal is serialized and abandonable, KEK rotation in real locked memory, running out of locked memory mid-hierarchy, a refused freeze, sweeps overlapping sealer use, configuration and misconfiguration. `sealer_lifecycle_test.go`, `sealer_lifecycle_linux_test.go`: destroyed sealers return their locked memory, an injected provider stays its owner's, destroy during a blocked unseal, a refused release is reported and retried. `enclave_test.go`: key-schedule erasure reports this build. `provider_test.go`: the software provider refuses misuse. |
| [shutdown-sweep](../../docs/shutdown-sweep/user.md) | `registry_test.go`: `WipeAll` reclaims everything and leaves no residue; waits for live borrows until its deadline; turns away a concurrent caller; reports canary corruption without panicking; reclaims an orphan a refused cleanup left; `SweepError` renders. `sealer_test.go`: a sealer is wiped for good after a sweep. |
| [provider-conformance](../../docs/provider-conformance/user.md) | `provider_test.go`: `SoftwareProvider` passes `TestProvider` in both modes with the residue sweep running, and an under-claimed mode list fails; in a child with `RLIMIT_MEMLOCK` at zero the sweep cannot run, and `TestProvider` reports `ErrNotMeasured` unless `SkipResidueSweep` accepts it. `provider_failure_test.go`: `TestProvider` run against a provider broken in one way at a time reports that property as a `PropertyError` and nothing else: a Protect or Unprotect that fails, writes the wrong bytes, keeps the caller's slice or an old destination, accepts a forged blob or a destination of the wrong length, ignores an ended context, shares state across concurrent calls, or keeps a heap copy of the key for the residue sweep; a RootUnsealer that fails, writes a placeholder or half a root, or retains its destinations; a bare public-key wrap that opens a blob built with `Config.Forge`; claimed modes the provider does not serve. An ended run context, or a provider call that never returns, gives `ErrAborted` with no findings; too little locked memory gives `ErrNotMeasured`; each invalid `Config` gives `ErrInvalidConfig` and a `ConfigError` for the field, with no provider built. |
| [backends](../../docs/backends/user.md) | `backend_test.go`: an enclave on the real kernel's locked memory reports the registered default backend, before and after `Destroy`, and `As` reaches its capabilities. `Register` refuses an invalid name, a duplicate, the default's name and a nil or typed-nil backend, each with its typed error, and accepts a valid one that `Lookup` and `BackendNames` then return; `Lookup` reports an unknown name. `As` covers assignable targets, a wrapper's `As` method, nil and typed-nil values and bad targets. `NewImportSpec` with `WithPurpose` and `WithAlgorithm` resolves valid combinations and refuses invalid ones with `ErrInvalidImport`. |

## Helpers

These files hold no feature tests; each is named for what it provides.

- `main_test.go`: `TestMain`, which refuses to run outside the devcontainer
  (`../internal/devcontainer`).
- `procfs_test.go`: the `/proc/self` oracle (status VmLck, smaps VmFlags, and a
  residue sweep that reports every address the material is at).
- `isolation_test.go`: re-runs a test in a fresh child process with its own
  limits.
- `provider_fakes_test.go`: the providers that break one property of the
  provider seam each, wrapped around a real `SoftwareProvider`, and the reading
  of a `TestProvider` verdict by type.
- `seccomp_test.go`: the seccomp fault injector that refuses chosen syscalls,
  and the tests of the injector itself.

The `/proc/self/mem` sweep the unit tests and `providertest` share is
`internal/memscan`. `procfs_test.go` keeps its own sweep because it asserts
more: exact addresses, every readable mapping including file-backed ones, a
needle that is never assembled in memory, and failure on any mapping it cannot
read.

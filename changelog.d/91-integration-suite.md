### Added

- **An integration suite that checks go-enclave's guarantees from the kernel's
  side** (#91). `test/integration/enclave/` (build tag `integration`) drives
  the public API (`MemoryEnclave`, `Allocator`, `Sealer`/`SealedEnclave`,
  `WipeAll`) the way a consumer does. It then reads the result back from the
  kernel instead of trusting the library's own report:
  - Admission runs against a real, unliftable `RLIMIT_MEMLOCK` ceiling. The
    allocator's accounting is checked against `/proc/self/status` `VmLck`. A
    budget refusal is told apart from a real `mlock` refusal at the ceiling.
    `SetLimit`, `ForceLimit` and `TransferTo` are exercised, and so is
    contention with the budget set exactly at the kernel ceiling. Zero-ceiling
    processes and both `ProcessAllocator` installation orders are covered too.
  - Every enclave, by every constructor and by `SealedEnclave.Open`, is shown
    by `/proc/self/smaps` to be `VM_LOCKED` and `VM_DONTDUMP`. Each is fenced
    by unlocked `PROT_NONE` guard pages, and has the permissions its frozen
    state calls for. Every locked mapping in the process, including the
    sealer's own keys, is excluded from core dumps. `RLIMIT_CORE` drops from a non-zero starting
    limit to 0/0 on import, and the process cannot raise it again.
  - Plaintext residue is checked by sweeping every readable mapping through
    `/proc/self/mem`. The material is findable where it is meant to live and
    absent everywhere after `Destroy`, after `WipeAll`, and from a
    `SealedEnclave` between opens.
  - Sealing runs end to end in both modes through an injected provider backed
    by `SoftwareProvider`, sealing and opening 1,024 values concurrently. The
    suite checks that a deadline reaches a blocked provider and that no lock
    is held across a provider call. It checks that the root is unsealed
    exactly once, and that the one-shot process `Sealer` behaves as
    documented. `providertest.TestProvider` runs against the shipped provider,
    with its residue sweep confirmed to have run.
  - `WipeAll` is tested with live borrows and a deadline, with a concurrent
    caller (`ErrSweepInProgress`), and with real canary corruption. That
    corruption is reported as `SweepError`, and `Destroy` panics only after
    wiping.

  Every test that touches process-global state runs in a fresh child process
  of its own.
- **`build/docker/devcontainer/`: the only place the suite runs.** The Go
  1.27.0 Alpine base is pinned by digest. The container runs as an
  unprivileged user with every capability dropped, `no-new-privileges`, a
  read-only root filesystem and no network. Its `memlock` and `core` ulimits
  are finite and declared. Modules are baked in and verified against
  `go.sum`, so runs work offline. The source is baked into the image, not
  bind-mounted, so the container is correct on a CI runner that reaches the
  host's Docker daemon. The suite refuses to run on the host, or in a
  container whose capabilities, limits or FIPS state differ from what
  `compose.yaml` declares.
- **`make integration-test`, `make integration-test-fips`, the per-package
  `integration-test-<pkg>` / `integration-test-fips-<pkg>`, and
  `make lint-integration`.** The FIPS variant runs the whole suite under
  FIPS 140-3 strict mode (`GOFIPS140=latest`, `GODEBUG=fips140=only`) and
  checks that the mode took effect. Each run is its own Compose project,
  torn down with its volume and image. `make ci` now includes both suites.
  `make ci-fast` and the CI Lint job run `lint-integration`, the tagged
  analysis the untagged `lint` cannot see. CI gains an `Integration` job,
  required by the CI Gate. `release.yml` runs the same three targets on the
  tagged commit, and the release publishes only if they pass.

### Added

- **Feature documentation under `docs/`** (#92), one folder per capability with
  `architecture.md`, `engineering.md`, `api.md`, `cli.md` and `user.md`:
  `docs/locked-memory` (`MemoryEnclave` lifecycle, the one panic, guard pages
  and canary, the per-GOOS platform and core-dump matrix), `docs/locked-memory-budget`
  (`Allocator`, `RLIMIT_MEMLOCK` discovery, retuning, the process allocator,
  refunds for failed constructions), `docs/sealing` (modes, the provider seam
  and its context contract, `Openable`, FIPS, the AES key-schedule heap
  exposure), `docs/shutdown-sweep` (`WipeAll(ctx)` admission, waits,
  termination and return values) and `docs/provider-conformance`
  (`providertest.TestProvider`). Mermaid diagrams cover the mapping layout,
  the release sequence, lock ordering and the sweep state machine.
- **An upgrade guide from v0.6** (#92): `docs/README.md` lists every breaking
  change since v0.6.2-alpha with before/after code in the relevant feature's
  `user.md`.
- **`SECURITY.md`** (#92): supported versions (only the latest release while
  pre-1.0), private reporting through the forge's vulnerability reporting,
  scope (memory exposure, residue, core-dump leaks, cryptographic misuse,
  provider-contract violations, build and release supply chain) and documented
  out-of-scope limits, response targets, coordinated disclosure, and links to
  the threat-model sections of `docs/`.

### Changed

- **README.md and the package documentation are an overview** (#92): what the
  library is, install, a quick start, the platform matrix, development and
  release targets, and links into `docs/`. The detailed material they carried
  now lives, verified against the code, in the feature folders.

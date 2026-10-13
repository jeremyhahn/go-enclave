# go-enclave roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-13
> Changes are proposed by docs-only PR.

## Mission

The portfolio locked-memory primitive: `Memory` (mlock, guard pages, canary) and the `WithBytes` borrow window.
A bounded `Allocator` that admits against a byte budget before allocating, with CAS admission.
`Sealed` keeps contents encrypted at rest and opens them into a fresh `Memory`.

## Current milestone

[Release candidate (M1)](../../milestone/1), target kind RC (v0.9.0-rc.1); projected: cuts when the open items below are done.
No other milestone is open.

## Now

Each line: issue, outcome, the `docs/<feature>/` folder that specifies it, status.

- [#138](../../issues/138) v0.9.0-rc.1 pre-RC review fixes and hardware-backend seam (umbrella) — `docs/backends/`, `docs/locked-memory/`, `docs/sealing/`, `docs/backend-conformance/` — open
- [#135](../../issues/135) backend seam for hardware enclaves (registry, injection, capabilities) — `docs/backends/` — done
- [#136](../../issues/136) release safety, analysis and build-gate fixes; [#137](../../issues/137) signed release artifacts (IS-14); [#140](../../issues/140) docs conformance for the Serena agent rule — no feature folder: build and release, specified in the [README](README.md#development) — done
- [#145](../../issues/145) rename `MemoryEnclave`, `SealedEnclave` and `OpenWith`; add `noCopy` — `docs/locked-memory/`, `docs/sealing/` — done
- [#146](../../issues/146) conformance suite, typed errors and `memscan` fail closed — `docs/provider-conformance/`, `docs/backend-conformance/` — done
- [#150](../../issues/150) docs match the exported API — every folder in the [index](docs/README.md) — done
- [#154](../../issues/154) FIPS 140-only backend fakes, `test-fips` gates every PR (PR [#155](../../pulls/155)) — `docs/sealing/`, `docs/backend-conformance/` — done
- [#156](../../issues/156) owner docs: backends — `docs/backends/`, `docs/backend-conformance/` — done
- [#157](../../issues/157) owner docs: locked memory — `docs/locked-memory/` — done
- [#158](../../issues/158) owner docs: budget and shutdown sweep — `docs/locked-memory-budget/`, `docs/shutdown-sweep/` — done
- [#159](../../issues/159) owner docs: sealing — `docs/sealing/`, `docs/provider-conformance/` — done
- [#160](../../issues/160) owner docs: roadmap and docs index — the [index](docs/README.md) — done
- [#163](../../issues/163) `ErrSealerNotConstructed` godoc matches the code — `docs/sealing/` — done
- [#164](../../issues/164) `WipeAll` godoc on `Sweeper` panics — `docs/shutdown-sweep/` — done
- [#165](../../issues/165) `KeyScheduleExposedError` wording in the #145 changelog fragment — `docs/sealing/` — done
- [#166](../../issues/166) GCM counter-block wording in backend-conformance engineering — `docs/backend-conformance/` — done
- [#167](../../issues/167) roadmap names the folder behind each item — the [index](docs/README.md) — done
- [#168](../../issues/168) spec-review scrub of `docs/` for the RC — every folder in the [index](docs/README.md) — done
- [#184](../../issues/184) property fuzz of the `Allocator` budget, seal/open round trip and constant-time helpers — `docs/locked-memory-budget/`, `docs/sealing/`, `docs/locked-memory/` — done
- [#183](../../issues/183) fuzz targets for parsing untrusted input, with the wipe-on-refusal fix (PR [#185](../../pulls/185)) — `docs/sealing/` — done
- readiness: `make release-candidate` passes on main — done
- readiness: [v0.8.0-rc.1](../../releases/tag/v0.8.0-rc.1) tag cut on 3ee5cb2, 2026-10-12 13:24Z — done
- readiness: post-tag consumer check, release run 49323 8/8 green, published 2026-10-12 16:42Z — done
- readiness: [v0.8.0-rc.2](../../releases/tag/v0.8.0-rc.2) tag cut on b5f772a, 2026-10-13 00:43Z — done
- readiness: post-tag consumer check, release run 50067 8/8 green, published 2026-10-13 00:56Z — done
- readiness: release-readiness checklist [#80](../../issues/80) — done

## Next

Nothing queued. New work arrives as issues.

## Later

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: none in-house; the only module dependency is `golang.org/x/sys` v0.48.0.
- Down: every Layer 0–3 library that touches raw key bytes consumes `Memory`.
- Handbook: handbook#275 (handbook names still say `MemoryEnclave`).

## Non-goals

- Process-wide lifecycle (`WipeAll`) belongs to the consuming binary; see [ownership](docs/locked-memory/architecture.md#component-boundaries).
- Everything outside the locked-memory primitive; see [ownership](docs/locked-memory/architecture.md#component-boundaries).

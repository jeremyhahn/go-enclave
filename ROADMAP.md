# go-enclave roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-11
> Changes are proposed by docs-only PR.

## Mission

The portfolio locked-memory primitive: `Memory` (mlock, guard pages, canary) and the `WithBytes` borrow window.
A bounded `Allocator` that admits against a byte budget before allocating, with CAS admission.
`Sealed` keeps contents encrypted at rest and opens them into a fresh `Memory`.

## Current milestone

[Release candidate (M1)](../../milestone/1), target kind RC (v0.9.0-rc.1).
Projected 2026-10-12.

## Now

- [#138](../../issues/138) v0.9.0-rc.1 pre-RC review fixes and hardware-backend seam (umbrella) — open
- [#135](../../issues/135) backend seam for hardware enclaves (registry, injection, capabilities) — done
- [#136](../../issues/136) release safety, analysis and build-gate fixes from the pre-RC review — done
- [#137](../../issues/137) signed release artifacts (IS-14) — done
- [#140](../../issues/140) docs conformance for the Serena agent rule — done
- [#145](../../issues/145) rename `MemoryEnclave`, `SealedEnclave` and `OpenWith`; add `noCopy` — done
- [#146](../../issues/146) conformance suite, typed errors and `memscan` fail closed — done
- [#150](../../issues/150) docs match the exported API — done
- [#154](../../issues/154) FIPS 140-only backend fakes, `test-fips` gates every PR (PR [#155](../../pulls/155)) — done
- [#156](../../issues/156), [#157](../../issues/157), [#158](../../issues/158), [#159](../../issues/159), [#160](../../issues/160) owner documentation programme — open
- readiness: `make release-candidate` passes on main — open
- readiness: v0.9.0-rc.1 tag cut — open
- readiness: post-tag consumer check — open
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

- Process-wide lifecycle (`WipeAll`) belongs to the consuming binary; see [ownership](../handbook/software/docs/00-ownership-and-sdk-boundary.md).
- Everything outside the locked-memory primitive; see [ownership](../handbook/software/docs/00-ownership-and-sdk-boundary.md).

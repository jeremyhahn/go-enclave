# go-enclave roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-14
> Changes are proposed by docs-only PR. Agrees with [docs/SPEC.md](docs/SPEC.md), which lists every feature named below.

## Mission

go-enclave is the enclave abstraction layer plus the default software memory enclave for hosts without hardware.
Upstream projects consume one clearly defined interface and never a concrete implementation or a pointer to one.
`Sealed` keeps contents encrypted at rest and opens them into a fresh `Memory`.
Its layer is the base of the stack, under go-quicraft: [SPEC purpose](docs/SPEC.md#purpose).
What it owns and never does: [SPEC boundaries](docs/SPEC.md#boundaries).

## Milestones

Each line: issue or fact, outcome, the SPEC feature it serves, status.

- [v0.9.0-rc.1](../../milestone/34), target kind RC; closes per [SPEC release criteria](docs/SPEC.md#release-criteria).
- [#138](../../issues/138) v0.9.0-rc.1 pre-RC review fixes and hardware-backend seam (umbrella); its trains [#135](../../issues/135), [#136](../../issues/136), [#145](../../issues/145), [#146](../../issues/146) and [#150](../../issues/150) are closed — enclave-interface, backends, memory-enclave, sealing, backend-conformance, build and release — open
- [#190](../../issues/190) — backend-detection — open
- [#188](../../issues/188) design, PR [#189](../../pulls/189) — BSD and Windows runtime testing — open
- [Release candidate (M1)](../../milestone/1), target kind RC — closed: 0 open, 11 closed issues.
- [#80](../../issues/80) release-readiness checklist (M1) — build and release — done
- [#163](../../issues/163) `ErrSealerNotConstructed` godoc matches the code (M1) — sealing — done
- [#164](../../issues/164) `WipeAll` godoc on `Sweeper` panics (M1) — shutdown-sweep — done
- [#165](../../issues/165) `KeyScheduleExposedError` wording in the #145 changelog fragment (M1) — sealing — done
- [#166](../../issues/166) GCM counter-block wording in backend-conformance engineering (M1) — backend-conformance — done
- [#167](../../issues/167) roadmap names the folder behind each item (M1) — build and release — done
- [#168](../../issues/168) spec-review scrub of `docs/` for the RC (M1) — build and release — done
- [#175](../../issues/175) tiered CI, small PR tier and full tier (M1) — build and release — done
- [#180](../../issues/180) `batch.yml` v1: fuzz, race-full, soak and bench on the batch runners (M1) — build and release — done
- [#183](../../issues/183) fuzz targets for parsing untrusted input, with the wipe-on-refusal fix (PR [#185](../../pulls/185)) (M1) — sealing — done
- [#184](../../issues/184) property fuzz of the `Allocator` budget, seal/open round trip and constant-time helpers (M1) — locked-memory-budget, sealing, memory-enclave — done
- readiness: `make release-candidate` passes on main — build and release — done
- readiness: [v0.8.0-rc.1](../../releases/tag/v0.8.0-rc.1) tag cut on 3ee5cb2 — build and release — done
- readiness: post-tag consumer check, release run 49323 8/8 green, published — build and release — done
- readiness: [v0.8.0-rc.2](../../releases/tag/v0.8.0-rc.2) tag cut on b5f772a — build and release — done
- readiness: post-tag consumer check, release run 50067 8/8 green, published — build and release — done

## Complete

Each line: SPEC feature, what shipped, the closing issues, the release. A feature's name is its `docs/<feature>/` folder; [SPEC](docs/SPEC.md#features) gives the folder of each. Every shipped feature is in [v0.8.0-rc.2](../../releases/tag/v0.8.0-rc.2).

- **memory-enclave** (`docs/locked-memory/`) — `Memory`: sized and copying constructors, `Freeze`, typed `Destroy` and release reporting, the OS layer on `golang.org/x/sys`, fork exclusion and opt-in `HardenProcess`, renamed from `MemoryEnclave` with `noCopy` — [#1](../../issues/1), [#6](../../issues/6), [#12](../../issues/12), [#13](../../issues/13), [#14](../../issues/14), [#29](../../issues/29), [#30](../../issues/30), [#86](../../issues/86), [#88](../../issues/88), [#109](../../issues/109), [#110](../../issues/110), [#145](../../issues/145); docs [#157](../../issues/157)
- **locked-memory-budget** — mandatory admission in locked pages, `RLIMIT_MEMLOCK` discovery, runtime retune, the process allocator, a guarded refusal path — [#2](../../issues/2), [#7](../../issues/7), [#11](../../issues/11), [#35](../../issues/35), [#46](../../issues/46), [#47](../../issues/47), [#71](../../issues/71); docs [#158](../../issues/158)
- **sealing** — `Sealed` encrypted at rest, the two-mode provider seam, budgeted and frozen opens, context-taking provider calls, KEK rotation, key-schedule erasure, typed provider options, FIPS 140-only fakes (`test-fips` gates every PR) — [#15](../../issues/15), [#17](../../issues/17), [#22](../../issues/22), [#34](../../issues/34), [#36](../../issues/36), [#87](../../issues/87), [#98](../../issues/98), [#99](../../issues/99), [#102](../../issues/102), [#107](../../issues/107), [#108](../../issues/108), [#145](../../issues/145), [#154](../../issues/154) (PR [#155](../../pulls/155)); docs [#159](../../issues/159)
- **shutdown-sweep** — cooperative `WipeAll(ctx)` that waits on borrows and reports a typed `SweepError` — [#18](../../issues/18), [#27](../../issues/27), [#33](../../issues/33), [#88](../../issues/88); docs [#158](../../issues/158)
- **provider-conformance** — `providertest` verifies a provider retains nothing, sweeps file-backed mappings and fails closed — [#64](../../issues/64), [#111](../../issues/111), [#146](../../issues/146); docs [#159](../../issues/159)
- **backends** — the backend seam: registry, injection, capabilities, `*Allocator` as the locked-memory backend, sealing wiring (`WithBackend`, `OpenIn`, `SealFrom`) — [#135](../../issues/135), [#145](../../issues/145); first in [v0.8.0-rc.1](../../releases/tag/v0.8.0-rc.1); docs [#156](../../issues/156)
- **backend-conformance** — `backendtest`, typed errors and `memscan` fail closed — [#146](../../issues/146), [#154](../../issues/154); docs [#156](../../issues/156)
- **build and release** — pinned tools and Makefile-driven CI, changelog fragments, the integration suite, `make release VERSION=…` for every release kind, release safety and build gates, signed release artifacts (IS-14), docs conformance for the Serena agent rule — [#48](../../issues/48), [#89](../../issues/89), [#91](../../issues/91), [#134](../../issues/134), [#136](../../issues/136), [#137](../../issues/137), [#140](../../issues/140); docs match the exported API, roadmap and docs index current to the RC — [#150](../../issues/150), [#160](../../issues/160)

## Now

- **enclave-interface** — [#138](../../issues/138), milestone v0.9.0-rc.1: the one public interface upstream consumes; constructors return it.

## Next

Nothing queued. New work arrives as issues.

## Later

- **backend-detection** — [#190](../../issues/190), milestone v0.9.0-rc.1.
- **BSD and Windows runtime testing** — [#188](../../issues/188) design, PR [#189](../../pulls/189), milestone v0.9.0-rc.1: test runners for the BSDs and Windows, which are build-only for the RC — no feature folder

## Future

Directions in no milestone.

- **se052f-secure-element** — a backend on the EdgeLock SE052F secure element implementing the backend seam ([#191](../../issues/191)) — `docs/backends/`
- **optiga-trust-m** — the host-side Go backend for the Infineon OPTIGA Trust M I2C element implementing the backend seam; trusted-firmware owns the on-device driver ([#196](../../issues/196)) — `docs/backends/`
- **mac-secure-enclave** — a backend on the Mac Secure Enclave implementing the backend seam ([#192](../../issues/192)) — `docs/backends/`
- **intel-sgx** — a backend on Intel SGX implementing the backend seam ([#193](../../issues/193)) — `docs/backends/`
- **amd-sev** — a backend on AMD SEV implementing the backend seam ([#194](../../issues/194)) — `docs/backends/`
- **imx-edgelock-enclave** — a go-enclave backend that binds the Linux side (xkmsd) to the trusted-imx95 secure world through that repo's interface, consumed by go-xkms's `hsm-appliance` feature ([#195](../../issues/195)) — `docs/backends/`
- **intel-tdx** — a backend on Intel TDX implementing the backend seam — `docs/backends/`
- **tpm** — a backend on a TPM implementing the backend seam — `docs/backends/`
- **nvidia-blackwell** — a backend on NVIDIA Blackwell confidential computing implementing the backend seam — `docs/backends/`

## Dependencies

- Up: none in-house, as the base layer it embeds no project; the only module dependency is `golang.org/x/sys` v0.48.0 — memory-enclave.
- Down: Every layer above, from go-quicraft up, consumes the enclave interface (enclave-interface) and re-exports it through its own SDK. Today luks2, xkms, quicraft, qrdb and quicbaas hold concrete pointers — memory-enclave, sealing, enclave-interface.
- Out of tree: the hardware backend rows depend on go-enclave, never the reverse; TPM, HSM and KMS providers belong to go-xkms — the hardware backend rows, sealing.
- trusted-firmware: owns the on-device C driver for the NXP EdgeLock SE052F as its element tier, and the on-device driver for the Infineon OPTIGA Trust M; go-enclave's backends for the same parts are the host-side Go backends — se052f-secure-element, optiga-trust-m.
- trusted-imx95: owns the i.MX 95 secure world and its secure key handling code; go-enclave's backend binds xkmsd to it through that repo's interface, and nothing device-specific is implemented here — imx-edgelock-enclave.
- Handbook: names match the `MemoryEnclave` → `Memory` and `SealedEnclave` → `Sealed` renames (handbook#275, closed) — memory-enclave, sealing.

# go-enclave roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-26
> Changes are proposed by docs-only PR. Agrees with [docs/SPEC.md](docs/SPEC.md), which lists every feature named below.

## Mission

go-enclave is the enclave abstraction layer plus the default software memory enclave for hosts without hardware; upstream projects consume one clearly defined interface and never a concrete implementation or a pointer to one.
`Sealed` keeps contents encrypted at rest and opens them into a fresh memory enclave.
Its layer is the base of the stack, under go-quicraft: [SPEC purpose](docs/SPEC.md#purpose); what it owns and never does: [SPEC boundaries](docs/SPEC.md#boundaries).

## Milestones

- First public release — target kind: release (`vX.Y.Z`), the version confirmed at the owner's publish approval — criteria: [SPEC release criteria](docs/SPEC.md#release-criteria)
- [v0.10.0 dev complete](../../milestone/39) — target kind: dev complete

## Complete

- **memory-enclave** — `Memory`: sized and copying constructors, `Freeze`, typed `Destroy` and release reporting, the OS layer on `golang.org/x/sys`, fork exclusion and opt-in `HardenProcess`, renamed from `MemoryEnclave` with `noCopy` — [#1](../../issues/1) — done
- **locked-memory-budget** — mandatory admission in locked pages, `RLIMIT_MEMLOCK` discovery, runtime retune, the process allocator, a guarded refusal path — [#2](../../issues/2) — done
- **sealing** — `Sealed` encrypted at rest, the two-mode provider seam, budgeted and frozen opens, context-taking provider calls, KEK rotation, key-schedule erasure, typed provider options, FIPS 140-only fakes — [#15](../../issues/15) — done
- **shutdown-sweep** — cooperative `WipeAll(ctx)` that waits on borrows and reports a typed `SweepError` — [#18](../../issues/18) — done
- **provider-conformance** — `providertest` verifies a provider retains nothing, sweeps file-backed mappings and fails closed — [#64](../../issues/64) — done
- **backends** — the backend seam: registry, injection, capabilities, `*Allocator` as the locked-memory backend, sealing wiring — [#135](../../issues/135) — done
- **backend-conformance** — `backendtest`, typed errors and `memscan` fail closed — [#146](../../issues/146) — done
- **build-and-release** — pinned tools and Makefile-driven CI, changelog fragments, the integration suite, `make release VERSION=…` for every release kind, release safety and build gates, signed release artifacts — [#48](../../issues/48) — done
- **backend-detection** — `Detect`, on an explicit call from `main`, selects the most secure of the registered backends by the rank each reports, the memory enclave when nothing else is usable — [#190](../../issues/190) — done
- **enclave-interface** — the one public interface upstream consumes; constructors return it — [#138](../../issues/138) — done
- **linux-secretmem** — a Linux-only software backend on `memfd_secret(2)`, ranked above the memory enclave and below every hardware backend — [#261](../../issues/261) — done
- **open-in-secretmem** — `Sealed.OpenIn` decrypts straight into a linux-secretmem handle's pages, with no scratch enclave or import — [#263](../../issues/263) — done

## Now

- **public-release** — the first public release: a release candidate through its tag workflow and staging, then `make release` at the version the owner confirms, published to GitHub with a tree byte-identical to the tag's — [release criteria](docs/SPEC.md#release-criteria) — in progress

## Next

- **keyprotector-providers** — the `KeyProtector` provider seam's planned providers (memory, TrustZone, secure element, TPM) and named consumers (go-xkms's `EnclaveBackend`, trusted-firmware's TA); the blob contract is [contract v1](docs/sealing/engineering.md#blob-contract-v1) — [#264](../../issues/264) — planned

## Later

Nothing queued.

## Future

- **mac-secure-enclave** — a backend on the Mac Secure Enclave implementing the backend seam — [#192](../../issues/192) — open
- **intel-sgx** — a backend on Intel SGX implementing the backend seam — [#193](../../issues/193) — open
- **amd-sev** — a backend on AMD SEV implementing the backend seam — [#194](../../issues/194) — open
- **imx-edgelock-enclave** — a backend that binds xkmsd to the trusted-imx95 secure world through that repo's interface — [#195](../../issues/195) — open
- **intel-tdx** — a backend on Intel TDX implementing the backend seam — [#199](../../issues/199) — open
- **nvidia-blackwell** — a backend on NVIDIA Blackwell confidential computing implementing the backend seam — [#200](../../issues/200) — open
- **arm-trustzone** — a host-side backend over the GlobalPlatform TEE Client API implementing the backend seam, on OP-TEE — [#206](../../issues/206) — blocked: waits on trusted-firmware's OP-TEE row

## Dependencies

- Up: none in-house, as the base layer it embeds no project; the only module dependency is `golang.org/x/sys` v0.49.0 — memory-enclave.
- Down: Every layer above, from go-quicraft up, consumes the enclave interface (enclave-interface) and re-exports it through its own SDK. Today luks2, xkms, quicraft, qrdb and quicbaas hold concrete pointers — memory-enclave, sealing, enclave-interface.
- Out of tree: the hardware backend rows depend on go-enclave, never the reverse; the TPM backend and TPM, HSM and KMS providers belong to go-xkms — the hardware backend rows, sealing.
- trusted-firmware: owns the on-device C driver for the NXP EdgeLock SE052F as its element tier, and the on-device driver for the Infineon OPTIGA Trust M; go-enclave declined host-side backends for those parts (no hardware; owner 2026-10-17). trusted-firmware also owns the OP-TEE secure world that go-enclave's TrustZone backend binds to — arm-trustzone.
- trusted-imx95: owns the i.MX 95 secure world and its secure key handling code; go-enclave's backend binds xkmsd to it through that repo's interface, and nothing device-specific is implemented here — imx-edgelock-enclave.
- Handbook: names match the `MemoryEnclave` → `Memory` and `SealedEnclave` → `Sealed` renames (handbook#275, closed) — memory-enclave, sealing.

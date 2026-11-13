# go-enclave roadmap

> **Status: REFERENCE** · Last verified: 2026-11-12
> Changes are proposed by docs-only PR. Agrees with [docs/SPEC.md](docs/SPEC.md), which lists every feature named below.

## Mission

go-enclave is an enclave abstraction layer for Go, plus a software memory enclave for hosts without enclave hardware; callers consume one interface and never a concrete type.
`Sealed` keeps contents encrypted at rest and opens them into a fresh enclave.
What it owns and never does: [SPEC purpose](docs/SPEC.md#purpose) and [SPEC boundaries](docs/SPEC.md#boundaries).

## Milestones

- First public release — target kind: release (`vX.Y.Z`) — criteria: [SPEC release criteria](docs/SPEC.md#release-criteria)
- [v0.10.0 dev complete](../../milestone/39) — target kind: dev complete

## Complete

- **memory-enclave** — `Memory`: sized and copying constructors, `Freeze`, typed `Destroy` and release reporting, the OS layer on `golang.org/x/sys`, fork exclusion and opt-in `HardenProcess` — [#1](../../issues/1) — done
- **locked-memory-budget** — mandatory admission in locked pages, `RLIMIT_MEMLOCK` discovery, runtime retune, the process allocator, a guarded refusal path — [#2](../../issues/2) — done
- **sealing** — `Sealed` encrypted at rest, the two-mode provider seam, budgeted and frozen opens, context-taking provider calls, KEK rotation, key-schedule erasure, typed provider options, FIPS 140-only fakes — [#15](../../issues/15) — done
- **shutdown-sweep** — cooperative `WipeAll(ctx)` that waits on borrows and reports a typed `SweepError` — [#18](../../issues/18) — done
- **provider-conformance** — `providertest` verifies a provider retains nothing, sweeps file-backed mappings and fails closed — [#64](../../issues/64) — done
- **backends** — the backend seam: registry, injection, capabilities, `Allocator` as the locked-memory backend, sealing wiring — [#135](../../issues/135) — done
- **backend-conformance** — `backendtest`, typed errors and `memscan` fail closed — [#146](../../issues/146) — done
- **build-and-release** — pinned tools and Makefile-driven CI, changelog fragments, the integration suite, `make release VERSION=…` for every release kind, release safety and build gates, signed releases — [#48](../../issues/48) — done
- **backend-detection** — `Detect`, on an explicit call from `main`, selects the most secure of the registered backends by the rank each reports, the memory enclave when nothing else is usable — [#190](../../issues/190) — done
- **enclave-interface** — the one public interface callers consume; constructors return it — [#138](../../issues/138) — done
- **linux-secretmem** — a Linux-only software backend on `memfd_secret(2)`, ranked above the memory enclave and below every hardware backend — [#261](../../issues/261) — done
- **open-in-secretmem** — `Sealed.OpenIn` decrypts straight into a linux-secretmem handle's pages, with no scratch enclave or import — [#263](../../issues/263) — done
- **arm-trustzone** — the nested module `backends/armtrustzone`, a backend over OP-TEE that passes `backendtest` on an OP-TEE fixture; design [docs/backends/arm-trustzone-design.md](docs/backends/arm-trustzone-design.md) — [#206](../../issues/206) — done

## Now

- **public-release** — the first public release: a release candidate through its tag workflow and staging, then `make release`, published to GitHub with a tree byte-identical to the tag's — [release criteria](docs/SPEC.md#release-criteria) — open
- **keyprotector-providers** — memory and TPM (`backends/tpm`) providers ship, and the TrustZone provider's host side; next are the trusted application's SEAL and UNSEAL on the OP-TEE fixture and the secure-element provider ([open questions](docs/sealing/hardware-providers.md#open-questions)) — [#264](../../issues/264) — open

## Next

None.

## Later

None.

## Future

- **mac-secure-enclave** — a backend on the Mac Secure Enclave implementing the backend seam — [#192](../../issues/192) — open
- **intel-sgx** — the process-enclave backend on Intel SGX implementing the backend seam — [#193](../../issues/193) — blocked: needs SGX hardware to test on (Xeon Scalable, Ice Lake-SP or newer, with Flexible Launch Control)
- **confidential-vm** — not a backend: an `Attester` for a process in an AMD SEV-SNP or Intel TDX confidential VM, through configfs-tsm, and an SEV-SNP derived-key `KeyProtector`; [proposal](docs/backends/confidential-vm.md) — [#194](../../issues/194) — open
- **imx-edgelock-enclave** — a backend on the NXP i.MX 95 EdgeLock Secure Enclave implementing the backend seam; [proposal](docs/backends/imx-edgelock-enclave.md) — [#195](../../issues/195) — open

## Dependencies

- Up: the root module requires only `golang.org/x/sys` v0.49.0; `backends/tpm` adds `github.com/google/go-tpm` v0.9.8; both nested modules require the root at v0.11.1-alpha — memory-enclave, keyprotector-providers, arm-trustzone.
- Down: every layer above, from go-quicraft up, consumes the enclave interface and re-exports it through its own SDK — enclave-interface, sealing.
- go-xkms: its `EnclaveBackend` keeps key material in `Sealed` envelopes; its TPM, PKCS#11 and cloud KMS key-operation backends stay in go-xkms — keyprotector-providers.
- trusted-firmware: supplies the OP-TEE trusted application the TrustZone backend binds to, pinned at v0.4.2-alpha in `scripts/tool-pins.sh`; its SEAL and UNSEAL commands are needed by the TrustZone provider — arm-trustzone, keyprotector-providers.
- Out of tree: the future hardware backend rows depend on go-enclave, never the reverse — the future backend rows.
- Standards watch: none; go-enclave implements no draft standard ([reference](docs/reference/README.md)).

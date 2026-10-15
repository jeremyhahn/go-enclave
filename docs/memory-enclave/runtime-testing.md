# Runtime testing on the BSDs and Windows — design proposal

> **Status: REFERENCE** · Scope: go-enclave · Last verified: 2026-10-13
> A proposal the owner approves before any implementation (#188). Nothing here
> is built yet: the Makefile, scripts and CI are unchanged.

The BSDs (freebsd, openbsd, netbsd, dragonfly) and Windows are build-only
([test status](engineering.md#test-status)); owner ruling M10 on #138 kept them
so for the RC and left test runners to this ticket. This document proposes how
the suite would execute on each of them under the devcontainer rule, with the
options and their trade-offs, and closes with the owner's decisions.

Facts about today's behavior cite the file or doc they come from. Facts about
tools and operating systems that this design has not verified are listed as
open questions ([§6](#6-open-questions)), not stated as true.

## 1. What runs today

`make cross-build` runs `go build` and `go vet` for every `CROSS_TARGETS` entry
([Makefile](../../Makefile), [scripts/cross-build.sh](../../scripts/cross-build.sh));
the BSDs are in it as `amd64`, Windows as `amd64` and `386`. `go vet`
type-checks `_test.go` files too, so the per-GOOS tests below compile on every
push and have never executed. Nothing is linked into a test binary and nothing
runs.

| GOOS | Platform files a run would exercise ([platform layer](engineering.md#platform-contract)) | Tests written for it, never run |
|---|---|---|
| freebsd, dragonfly | `osmem_unix.go`; `madvise_bsd.go` + `madvise_unix.go` (`MAP_NOCORE`, verified with `MADV_NOCORE`); `memlock_bsd.go`; `harden_unsupported.go` | `memlock_bsd_test.go`, `osmem_unix_test.go`, `harden_unsupported_test.go`, `backendtest/frozenhead_unix_test.go`, `providertest/residue_unsupported_test.go`, `internal/memscan/memscan_unsupported_test.go` |
| openbsd | `osmem_unix.go`; `madvise_openbsd.go` + `madvise_unix.go` (`MAP_CONCEAL` on the `mmap`); `memlock_bsd.go`; `harden_unsupported.go` | as freebsd |
| netbsd | `osmem_unix.go`; `madvise_unsupported.go` (no-op hooks); `memlock_bsd.go`; `harden_unsupported.go` | as freebsd |
| windows | `osmem_windows.go` (`VirtualAlloc`, `VirtualLock`, `PAGE_NOACCESS` guards); `madvise_unsupported.go`; `memlock_unsupported.go` (`LimitUnsupported`); `harden_unsupported.go` | `osmem_windows_test.go`, `memlock_unsupported_test.go`, `harden_unsupported_test.go`, `backendtest/frozenhead_windows_test.go`, `providertest/residue_unsupported_test.go`, `internal/memscan/memscan_unsupported_test.go` |

The BSD limit discovery is the same gap seen from the budget side
([discovery contract](../locked-memory-budget/engineering.md#platform-contract-for-discovery)).

**Linux-specific tests and why.** Each is described where it is owned; this
table only names the Linux interface that pins it.

| Test group | Linux interface it reads or needs | Described in |
|---|---|---|
| Kernel-recorded dump and fork exclusion | `/proc/self/smaps` `VmFlags` (`dd`, `dc`, `lo`) | [test strategy](engineering.md#test-strategy) |
| Locked-memory exhaustion and rollback | `RLIMIT_MEMLOCK` lowered in a subprocess, `CAP_IPC_LOCK` dropped per thread, `/proc/self/status` `VmLck` | [test strategy](engineering.md#test-strategy), [budget](../locked-memory-budget/engineering.md#test-strategy) |
| Fail-closed construction | seccomp `SECCOMP_RET_ERRNO` filters on `madvise` and `prctl` | [test strategy](engineering.md#test-strategy) |
| User namespaces | `CLONE_NEWUSER`, `/proc/self/uid_map` | [test strategy](engineering.md#test-strategy) |
| `HardenProcess` non-dumpable step | `PR_GET_DUMPABLE` | [test strategy](engineering.md#test-strategy) |
| Residue sweeps | `/proc/self/maps` and `/proc/self/mem` ([internal/memscan](../../internal/memscan/memscan_linux.go)) | [test strategy](engineering.md#test-strategy), [provider conformance](../provider-conformance/engineering.md) |
| Integration suite | its devcontainer contract reads the compose environment and `/proc/self/status`, and imports `x/sys/unix` ([devcontainer.go](../../test/integration/internal/devcontainer/devcontainer.go)) | [test strategy](engineering.md#test-strategy) |

## 2. Constraints every option meets

- **The devcontainer rule.** Every build and test runs in the toolchain image,
  nothing is installed on a host (`CLAUDE.md`; handbook `devcontainer.md`). A
  BSD or Windows process cannot run inside a Linux container, so execution
  happens in a guest operating system. The handbook already names this case: a
  stage needing "a second OS image" is named as such and runs only in CI
  (handbook `testing-guidelines.md` §6), and the feature's `engineering.md`
  lists the tests only CI runs. Lanes have no Docker and cannot run it.
- **No skip guards.** A test that cannot run on a GOOS is excluded by its file's
  build constraint, as `_linux_test.go` files are today, never by `t.Skip`
  (handbook `testing-guidelines.md`).
- **Make is the contract.** CI calls only `make` targets, and each reproduces
  locally (handbook `devops.md` §4). A new execution path is a new target.
- **The suite's own requirements hold in the guest.** The root package's
  `TestMain` exits 2 when the soft `RLIMIT_MEMLOCK` is bounded below 2 MiB
  (an unbounded or unsupported limit passes) ([memlock_test.go](../../memlock_test.go)); `make test`
  passes `-race -count=1 -cpu=1,2,8 -timeout=900s` and none is optional
  ([Makefile](../../Makefile)).
- **Runners belong to the Company Agent.** CI jobs run on the bare runner;
  this repository's runner labels are `ci-gate` and `batch`
  ([.github/actionlint.yaml](../../.github/actionlint.yaml)). Anything an option
  needs beyond those is a request, listed with the option, not an assumption.

## 3. Options

### A. Guests driven from a container stage (QEMU)

A new devcontainer stage, `FROM base` like the others, carries QEMU and the
tools to build a seed disk. The flow, per target:

1. In the toolchain image, `go test -c` builds one test binary per package for
   the target `GOOS/GOARCH`, as the existing images build everything else.
   `testdata/` is copied beside the root package's binary.
2. The binaries, and a script that runs each with the `make test` flags
   (`-test.count=1 -test.cpu=1,2,8 -test.timeout=900s`), go onto a read-only
   seed disk.
3. The stage boots a pinned guest image with the seed disk attached and no
   network, which keeps the integration service's `network_mode: none`
   posture. The guest runs the script as an unprivileged user with the memlock
   limit the suite requires, writes `go test` output to the serial console, and
   powers off.
4. The host side reads the console log and fails unless it holds the guest's
   end marker and a passing exit status for every package.

| | |
|---|---|
| Needs | QEMU and an image builder in the stage (Alpine packages, Q8); one guest image recipe per GOOS, built from upstream release media and pinned by SHA-256 in `scripts/tool-pins.sh` (the one pin file); from the Company Agent, a runner label whose job containers can open `/dev/kvm` (Q1), disk for the images, and the label in `actionlint.yaml` |
| CI time | One boot plus the suite per target; to be measured in the FreeBSD spike. Without KVM the guest runs under software emulation, far slower (Q2) |
| Maintenance | One recipe per GOOS, bumped with each OS release; the stage's tools are pinned like every other tool |
| Observes | `mlock` against the guest kernel's real `RLIMIT_MEMLOCK`; whether `MAP_NOCORE`/`MADV_NOCORE` and `MAP_CONCEAL` are accepted; guard-page and frozen-page faults; real limit discovery; on Windows, `VirtualLock` and `VirtualUnlock` on a real kernel |
| Does not observe | `-race`, unless the binaries can be cross-built with it (Q6); behavior specific to bare metal; whether excluded pages are really absent from a core, unless a core-inspection test is written ([§4](#4-which-tests-run-where)); host dump policy on Windows (WER `LocalDumps`) |
| Reproducible locally | Yes, on a developer machine with KVM, through the same target |

### B. Native self-hosted runners

A machine or VM per GOOS registered as a runner with its own label, running
`go test` natively.

| | |
|---|---|
| Needs | A runner build for each OS (Q9); the Go toolchain and tool pins installed on each host, which the devcontainer rule forbids, so a handbook exception first; five more machines for the Company Agent to keep patched |
| CI time | Lowest: no boot, native builds |
| Maintenance | Highest: five operating systems, and a second copy of every pin to keep in step |
| Observes | As A, plus `-race` where the platform supports it (Q6), since builds are native with cgo |
| Does not observe | As A, less the `-race` gap |
| Reproducible locally | Only on the same OS |

### C. Hosted runners on the github.com mirror

The Windows hosted runner natively, and third-party actions that boot a BSD VM
on an Ubuntu runner.

| | |
|---|---|
| Needs | Jobs guarded to github.com, since the Gitea plane has no such runners and an unknown `runs-on` label waits forever (handbook `devops.md` §1); every third-party action pinned by commit; Go installed in each job |
| CI time | Moderate; no infrastructure of ours |
| Maintenance | Low for us; behavior changes with the actions' upstreams |
| Observes | As B on hosted machines |
| Does not observe | Anything on the Gitea plane: dev pushes and trains get no result |
| Reproducible locally | No: outside both the devcontainer and the Makefile contract |

### D. Emulation layers (rejected)

Running the Windows binaries under Wine would observe Wine's `VirtualLock`, not
Windows'. A pass would say nothing about the platform-contract row.

### E. Link the test binaries in `cross-build` (complement, not an answer)

`go test -c` for every `CROSS_TARGETS` entry would catch link failures that
`go vet` cannot, at little cost and with no new infrastructure. It observes
nothing at run time and does not close #188; it can land with any option.

### Summary

| | A | B | C |
|---|---|---|---|
| Devcontainer rule | Kept (CI-only stage, testing-guidelines §6) | Needs an exception | Not kept |
| Runs on Gitea and github.com | Both, where the label exists | Both, where the label exists | github.com only |
| `make` reproduces it | Yes | Yes, on that OS | No |
| `-race` | Q6 | Yes, where supported | Yes, where supported |
| New infrastructure | One KVM runner label | Five hosts | None |

## 4. Which tests run where

| Group | BSDs | Windows |
|---|---|---|
| Portable unit tests (no build constraint) in all four packages, including the fuzz targets' seed corpora | Unchanged, once the guest's memlock limit meets `TestMain` (Q3) | Unchanged; `TestMain` passes on `LimitUnsupported`, but `VirtualLock` may refuse once the working set is exhausted (Q5) |
| Per-GOOS tests already written ([§1](#1-what-runs-today)) | Unchanged; these are the first observers | Unchanged |
| Guard-page and frozen-page faults (`mapping_linux_test.go`, `enclave_linux_test.go`) | Variant: the re-executed child is portable, but `requireChildFaulted` asserts the runtime's `SIGSEGV` report, and the signal a BSD delivers for the store is Q4 | Variant: the runtime reports an access violation, not `SIGSEGV` (Q4) |
| Exhaustion and rollback against a real ceiling (`enclave_linux_test.go`, `mapping_linux_test.go`, `allocator_linux_test.go`, `memlock_linux_test.go`, `sealed_linux_test.go`, `sealer_cleanup_linux_test.go`, `registry_linux_test.go`) | Variant: `setrlimit(RLIMIT_MEMLOCK)` in a subprocess carries over; the `CAP_IPC_LOCK` drop does not apply; `VmLck` needs a per-OS locked-bytes reader (Q10) | Variant: no rlimit; the ceiling would be the working set, lowered in the child, read back per page (Q5, Q10) |
| Dump exclusion recorded by the kernel (`TestNewMapping_KernelRecordsTheExclusions`) | Variant for freebsd, dragonfly and openbsd: dump a child's core with the limit raised and search it for the canary pattern, proving `MAP_NOCORE` or `MAP_CONCEAL` end to end; netbsd has no exclusion to observe | None: no exclusion ([platform contract](engineering.md#platform-contract)) |
| `madvise` refusal reporting (`TestExcludeFromCoreDump_ReportsRefusal`) | Variant where `madvise_unix.go` makes the call | None |
| smaps `VmFlags`, `MADV_DONTFORK`, seccomp, user namespaces, `PR_GET_DUMPABLE` | Linux-only | Linux-only |
| Residue sweeps (`internal/memscan`, `providertest` residue, `TestWipeAll_LeavesNoResidentMaterial`, `TestSealed_NoPlaintextInProcessMemory`) | Linux-only unless D6 asks for a per-OS scanner; `providertest` already reports `ErrNotMeasured` off Linux ([provider conformance](../provider-conformance/engineering.md)) | As BSDs |
| Integration suite (`test/integration/enclave`) | Linux-only: its devcontainer contract is Linux's ([§1](#1-what-runs-today)) | Linux-only |

Variants follow the existing pattern: a `_<goos>_test.go` file per behavior,
sharing the portable child-process helpers, which would move out of the
`_linux` files.

## 5. Recommendation and order

**Recommendation.** Option A for all five, run first from `batch.yml` on a KVM
runner label and promoted to the CI Gate once its time fits the gate's budget
(D3). For Windows, A if a Windows guest image can be licensed and pinned (D2);
otherwise C for Windows alone, as an interim. Land E alongside.

**Order.** Each step is done when the suite passes on that GOOS and its
[test status](engineering.md#test-status) changes from build-only to run.

1. **FreeBSD.** Proves the harness on the GOOS with the most distinct BSD code:
   the `MAP_NOCORE` path verified with `MADV_NOCORE`, and `memlock_bsd.go`.
   Its portable and per-GOOS tests first, then the fault and exhaustion variants.
2. **Windows**, once D2 is ruled: the largest untested surface, its own `osmem`
   and `memlock` files. If D2 is open, OpenBSD goes second.
3. **OpenBSD**: the only GOOS compiling `madvise_openbsd.go` (`MAP_CONCEAL`).
4. **DragonFly**: the FreeBSD files on another kernel; cheap once step 1 exists.
5. **NetBSD**: `memlock_bsd.go` on another kernel and no dump exclusion; the
   least code no earlier step observed.

**Owner decisions.**

- D1. Approve option A (QEMU guests from a container stage) for the BSDs.
- D2. Windows: A with a licensed, pinned Windows image; C on the github.com mirror only; or B.
- D3. Where it runs: `batch.yml` only, or the CI Gate once a run fits a stated time budget.
- D4. `-race` off Linux: accept guest runs without it, or build in the guest, which puts Go in the guest image.
- D5. Guest images: built in this repository from upstream media by a pinned recipe, or supplied by the Company Agent's runner infrastructure.
- D6. Residue sweeps and core inspection off Linux: new per-OS test code, or Linux-only with the documented `ErrNotMeasured`.
- D7. The integration suite stays Linux-only (recommended), or gets a guest contract of its own.
- D8. Confirm the guest stage is testing-guidelines §6's "second OS image" case, or rule a handbook change.

## 6. Open questions

To be settled in the FreeBSD spike or by the Company Agent, not assumed:

- Q1. Whether a runner can give job containers `/dev/kvm`, and under which label.
- Q2. The slowdown of software emulation against KVM for this suite, measured.
- Q3. Each BSD's default locked-memory limit for an unprivileged user (login class, system-wide wired-page limits, any switch on unprivileged `mlock`), and what the guest image must set to meet 2 MiB.
- Q4. Which signal each BSD delivers for a store to a `PROT_NONE` page, and how the Go runtime reports an access violation on Windows.
- Q5. How far `VirtualLock` reaches under a default working-set minimum, and whether the suite fits or a test must raise it.
- Q6. Which targets support `-race`, and whether a race-enabled test binary can be cross-built from the Alpine toolchain image.
- Q7. Upstream installable or VM images for each BSD release, and how each is installed unattended; and the licensing of a Windows guest image for CI.
- Q8. Whether Alpine packages QEMU and a seed-disk builder at versions the pin file can hold.
- Q9. Whether the runner software builds and runs on each BSD (option B only).
- Q10. Which interface reports a process's locked or wired bytes, and per-page lock state, on each BSD and on Windows.

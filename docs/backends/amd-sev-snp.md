# amd-sev-snp backend — design

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-11-21
> Conflicts with this document are defects. The module `backends/amdsev` is canonical: where it and this document disagree, fix this document to match it.
> The design and test plan of SPEC row [confiner-sev-snp](../SPEC.md#features): a backend that implements the [backend seam](architecture.md) and `Confiner` for a process inside an AMD SEV-SNP guest. It supersedes the Attester and KeyProtector parts of the earlier [confidential-vm proposal](confidential-vm.md).

## Problem

A process in a virtual machine shares its memory with the hypervisor, the host
kernel and the host's devices. An AMD SEV-SNP (Secure Encrypted Virtualization
with Secure Nested Paging) guest closes those paths in hardware: every private
page is encrypted with a key the host never holds, and the Reverse Map Table
refuses host writes, remaps and replays. The memory enclave and
linux-secretmem already keep material locked, guarded and out of core dumps;
inside an SNP guest the same pages are also out of the host's reach.

The backend seam has a capability for exactly this: `Confiner`
(`ConfinesProcess`), which reports that the process runs inside the
backend's boundary. Nothing in the tree claims it today. This backend claims
it, and only where it is true.

## Scope

- **In:** detecting, from userspace, that the process runs in an SEV-SNP
  guest; the backend seam and `Confiner`; handles that are the root module's
  locked-memory enclaves; `backendtest` inside an SNP guest; proof that the
  host cannot find the material.
- **Out:** attestation of the guest (SNP attestation reports, certificate
  chains, verification) and hardware key protectors (the SNP derived key).
  Both belong to go-xkms ([SPEC scope](../SPEC.md#scope)). The backend
  requests a report only during detection, to read its own guest's policy;
  it verifies no signature, returns no report and derives no key.
- **Out:** Intel SGX, Intel TDX and Arm CCA, which stay in the `confiner` row.

## Shape

- **A nested module, `backends/amdsev`** (package `amdsev`), with its own
  `go.mod`. It requires a released root module and `golang.org/x/sys`, never
  the reverse, as `backends/armtrustzone` does
  ([out-of-tree backend](architecture.md#an-out-of-tree-backend)).
- **`New(a enclave.Allocator) (enclave.Backend, error)`** returns the backend
  only inside an SNP guest whose policy forbids debugging. Its handles draw
  on `a`; a nil `a` is `enclave.ErrAllocatorNotConstructed`. Nothing happens at import, and nothing is registered: `main` calls
  `enclave.Register` with the value `New` returned.
- **Capabilities, exactly:** `CapabilityConfine` and `CapabilityImport`.
  `ConfinesProcess()` returns true: `New` succeeded only inside an SNP guest
  the host cannot debug, whose private memory holds the whole process. The answer is fixed for the
  backend's life and never blocks, as `Confiner` requires.
- **Handles are the root's locked-memory enclaves** (`enclave.NewMemorySized`
  and `enclave.NewMemoryCopy`, drawn on the allocator `New` was given). SNP adds
  nothing per handle inside the guest: the guest kernel and guest root read
  the process's memory as they would outside a CVM
  ([why not a backend](confidential-vm.md#why-not-a-backend)). What the
  backend adds is the claim, which a caller can require with
  `enclave.As[enclave.Confiner]`.
- **Linux only.** On any other OS a stub compiles whose `New` returns the
  typed error below, so a cross-platform `main` that links the module builds
  everywhere. On Linux off amd64 no SNP guest interface exists, and `New`
  refuses as it does on a host.

## Detecting an SNP guest from userspace

`New` accepts the environment only when the guest kernel itself has enabled
SNP and the firmware reports a guest policy that forbids debugging. It asks
two kernel interfaces for an attestation report, in order, and the first that
returns one decides:

1. **`/dev/sev-guest`** (`CONFIG_SEV_GUEST`, Linux 5.19). The kernel registers
   the `sev-guest` platform device only when SNP is active in the guest, and
   the driver binds only then: it needs the secrets page and the VM platform
   communication keys that the AMD Secure Processor places in an SNP guest at
   launch. `New` opens the device read-write, as its ioctls require (the
   device is root-only by default), and issues `SNP_GET_REPORT` at VMPL 3,
   the least privileged level, with zero report data. The firmware's
   `MSG_REPORT_RSP` must carry status 0 and a report of 1184 bytes; `New`
   then closes the device.
2. **The configfs-tsm `sev_guest` provider** (`CONFIG_TSM_REPORTS`, Linux 6.7,
   `/sys/kernel/config/tsm/report`), tried when the device step fails. `New`
   creates a report entry, reads its `provider` attribute, which must be
   `sev_guest` (a TDX guest reads `tdx_guest` here and is refused), writes
   `privlevel` 3 and 64 zero bytes to `inblob`, reads the 1184-byte report
   from `outblob`, and removes the entry. A failed `mkdir`, whether configfs
   is missing or refuses (`ENOENT`, `EACCES`, `EPERM`), is a refusal, never a
   skip.

**The guest policy.** Whichever interface returns the report, `New` reads its
64-bit `POLICY` field (offset `08h` of `ATTESTATION_REPORT`) and refuses when
the `DEBUG` bit, bit 19, is set: a guest launched with it allows the host to
debug it, which decrypts its memory. The report reaches the guest through the
firmware's encrypted guest messages, so the host cannot rewrite the policy in
it. A device report with `DEBUG` set is final; `New` does not try configfs-tsm
after it. The report's signature is not verified, and the report is not kept
or returned: verifying evidence is attestation, which is go-xkms's.

**Why a CPUID flag alone does not prove SNP.** CPUID leaf `0x8000001F`
reports what the processor supports (SME, SEV, SEV-ES, SEV-SNP), not what this
guest runs under. Outside SNP the hypervisor intercepts CPUID and returns
whatever it chooses, so a plain KVM guest, or an SEV or SEV-ES guest, can see
the SNP bit set. The guest's actual state is the `SEV_STATUS` MSR
(`0xC0010131`), which only the guest kernel reads; the kernel acts on it, and
`/dev/sev-guest` and the `sev_guest` provider are how that decision reaches
userspace. Inside an SNP guest the kernel's CPUID values come from the
firmware-checked SNP CPUID page, but userspace cannot tell those values from
a hypervisor's, so `New` never reads CPUID.

## Error contract

Every refusal is a typed error from the module's own `errors.go`, in the shape
the root uses ([errors.go](../../errors.go)):

| Failure | Error |
|---|---|
| `/dev/sev-guest` cannot be opened: the host, a plain KVM guest, an SEV or SEV-ES guest without SNP (`ENOENT`), or a process the device refuses (`EACCES`) | `*GuestError{Path: "/dev/sev-guest", Op: "open", Cause}` matching `ErrSNPGuestUnavailable`; `Cause` the `*os.PathError` |
| `SNP_GET_REPORT` fails, or the firmware answers with a non-zero status or a report of the wrong size | `*GuestError{Op: "report", Cause}`; `Cause` the `*os.SyscallError`, or a `*ReportError` matching `ErrReportRefused` |
| The report's `POLICY` has `DEBUG` set, from either interface | `*GuestError{Op: "policy", Cause}`; `Cause` a `*PolicyError` matching `ErrDebugPolicy`, carrying the policy |
| configfs-tsm missing or refused (`mkdir`), its `provider` unreadable or not `sev_guest` (`provider`, `Cause` a `*ProviderError` matching `ErrWrongProvider`), a refused `privlevel` or `inblob` write, an unreadable or short `outblob` (`outblob`, a `*ReportError`), or an entry it cannot remove (`rmdir`) | `*GuestError` with that `Op` and the configfs path; it is the device step's `Next` |
| Not Linux | `*GuestError{Op: "platform", Cause: errors.ErrUnsupported}` matching `ErrSNPGuestUnavailable` |
| A nil allocator | `enclave.ErrAllocatorNotConstructed` |
| A handle failure (budget, `mlock`, invalid spec) | the root's typed error, unchanged |

Every `*GuestError` matches `ErrSNPGuestUnavailable`. It has `Is` and
`Unwrap`, which returns `Cause` and `Next`, so `errors.Is` also matches the
errno and the cause's own sentinel. A refused `New` returns a nil backend and claims nothing: no
`Confiner` value ever exists outside an SNP guest. A refusal never falls back
to another backend; the program's `Detect` or its own code chooses.

## Test plan

The backend is proven inside a real SEV-SNP guest on an AMD EPYC host with
SEV-SNP (Zen 3 or later). No simulator or emulated platform stands in for it.
QEMU is the VMM driving KVM on that CPU, never TCG. The plan runs as the
self-hosted hardware job, `make integration-test-amd-sev`; unit tests cover
only what touches no device: every detection step and refusal, including a
report with the `DEBUG` policy bit from each interface, through a fake of the
kernel calls, and the error texts and unwrapping.

1. **Record the host.** Each run records the CPU family, model and stepping,
   the AMD Secure Processor firmware's SNP API version, the host kernel
   version (KVM with SNP support, `kvm_amd` `sev_snp=1`), and the QEMU and
   OVMF versions, in the job log.
2. **A fresh, pinned guest image per run.** The image's inputs are pinned by
   version and checksum: an OVMF build with SEV-SNP support (edk2
   `OvmfPkg/AmdSev`), a direct-boot guest kernel with `CONFIG_SEV_GUEST`,
   `CONFIG_TSM_REPORTS` and `CONFIG_AMD_MEM_ENCRYPT`, an initrd that carries
   the test binaries and runs them, and the kernel command line. QEMU boots it
   with the `sev-snp-guest` object and kernel hashes on, guest policy debug
   off, no migration agent. Each run boots a new guest and discards it.
3. **`backendtest` in the guest.** `backendtest.TestBackend` runs inside the
   SNP guest as root, with `BackendCapabilities` exactly `CapabilityConfine`
   and `CapabilityImport`. It passes, `ConfinesProcess()` is true and stable,
   and the same run as a non-root user gets the `open` refusal, with the
   configfs-tsm step's refusal as its `Next`, where both deny it.
4. **The host scan and its control.** In the SNP guest the test holds a fresh
   random needle in an enclave from the backend, and signals readiness over
   the serial console without writing the needle anywhere. On the host, as
   root, a scan of the VMM process's memory (`/proc/<pid>/maps` and
   `/proc/<pid>/mem`, the scan `internal/memscan` does in-process) must not
   find the needle. The control boots the same image as a plain KVM guest,
   where the same scan must find it; a control that does not find it fails
   the job, because then the scan proves nothing.
5. **The refusal cases.** `New` returns `ErrSNPGuestUnavailable` with the
   step named, and claims nothing, on the host itself, in a plain KVM guest,
   in an SEV guest and in an SEV-ES guest booted from the same image.

### Running it

The suite is `backends/amdsev/integration`, in the `backends/amdsev` module
behind the `amdsev` build tag, so neither the root module nor
`make test-backends` builds a test that needs the hardware.
`make integration-test-amd-sev` runs it through `scripts/amd-sev-snp/run.sh`
on the host. `AMDSEV_GUESTS` lists the encrypted guests to boot, from `sev`,
`sev-es` and `snp` (default `sev sev-es`); the plain KVM control always boots
beside them. The hardware host provides SEV and SEV-ES, so the job runs the
refusal cases (item 5) and the host scan in those guests; the SEV-SNP tests
(items 3 and 4 in an SNP guest) run where SNP is available, with `snp`
listed. A host that cannot run a listed mode fails the run naming what is
missing.

The workflow `.github/workflows/amd-sev.yml` has two hardware jobs. The
`amd-sev` job runs the target for `sev sev-es` on the self-hosted runner
labelled `amd-sev`, and starts only while the repository variable
`AMD_SEV_RUNNER` is `online`. That host has SEV and SEV-ES and no SEV-SNP,
and the job runs no SNP step.

The `amd-sev-snp` job runs the target with `AMDSEV_GUESTS=snp`, the SNP guest
and its plain KVM control, on the self-hosted runner labelled `amd-sev-snp`.
It starts only while the repository variable `AMD_SEV_SNP_RUNNER` is
`online`, and its first check fails the job, with an error annotation, unless
`kvm_amd` reports `sev_snp` as `Y` or `1`: a green run of it is an SNP run.

**Open:** the SNP hardware acceptance, items 3 and 4 in an SNP guest, has
not run. The `amd-sev-snp` job runs once an SEV-SNP host is registered as
that runner and the variable is set; until then the row stays in progress.

## What it does not do

- It does not attest. Evidence of the guest is go-xkms's.
- It does not derive or hold keys; the SNP derived key is go-xkms's.
- It does not isolate inside the guest: the guest kernel, guest root and
  `ptrace` in the guest reach the material as they would outside a CVM.
- It does not protect what the program writes to a socket, disk or console:
  those pass through shared pages the host reads.

## References

- [AMD SEV-SNP firmware ABI specification](https://www.amd.com/en/developer/sev.html)
  (AMD publication 56860, revision 1.58, pinned in the
  [reference index](../reference/README.md#amd-sev-snp)): the guest messages,
  `MSG_REPORT_RSP`, the `ATTESTATION_REPORT` and its `POLICY` field, the
  guest policy's `DEBUG` bit and the `SEV_STATUS` MSR.
- Linux `include/uapi/linux/sev-guest.h`
  ([copy](../reference/linux-uapi-sev-guest.h)): `SNP_GET_REPORT` and its
  request and response structs.
- Linux `Documentation/virt/coco/sev-guest.rst`: `/dev/sev-guest`.
- Linux `Documentation/ABI/testing/configfs-tsm`: the configfs-tsm report
  interface and its `provider`, `privlevel`, `inblob` and `outblob`
  attributes.
- [confidential-vm proposal](confidential-vm.md): the earlier design, whose
  kernel-interface and threat-model sections still apply.

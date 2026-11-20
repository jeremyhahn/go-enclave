# amd-sev-snp backend — design

> **Status: NORMATIVE** · Scope: go-enclave · Last verified: 2026-11-20
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
  requests no report and derives no key.
- **Out:** Intel SGX, Intel TDX and Arm CCA, which stay in the `confiner` row.

## Shape

- **A nested module, `backends/amdsev`** (package `amdsev`), with its own
  `go.mod`. It requires a released root module and `golang.org/x/sys`, never
  the reverse, as `backends/armtrustzone` does
  ([out-of-tree backend](architecture.md#an-out-of-tree-backend)).
- **`New() (enclave.Backend, error)`** returns the backend only inside an SNP
  guest. Nothing happens at import, and nothing is registered: `main` calls
  `enclave.Register` with the value `New` returned.
- **Capabilities, exactly:** `CapabilityConfine` and `CapabilityImport`.
  `ConfinesProcess()` returns true: `New` succeeded only inside an SNP guest,
  whose private memory holds the whole process. The answer is fixed for the
  backend's life and never blocks, as `Confiner` requires.
- **Handles are the root's locked-memory enclaves** (`enclave.NewMemorySized`
  and `enclave.NewMemoryCopy`, drawn on the process allocator). SNP adds
  nothing per handle inside the guest: the guest kernel and guest root read
  the process's memory as they would outside a CVM
  ([why not a backend](confidential-vm.md#why-not-a-backend)). What the
  backend adds is the claim, which a caller can require with
  `enclave.As[enclave.Confiner]`.
- **Linux on amd64 only.** On any other target a stub compiles whose `New`
  returns the typed error below, so a cross-platform `main` that links the
  module builds everywhere.

## Detecting an SNP guest from userspace

`New` accepts the environment only when the guest kernel itself has enabled
SNP, and reads that decision from two kernel interfaces:

1. **`/dev/sev-guest`** (`CONFIG_SEV_GUEST`, Linux 5.19). The kernel registers
   the `sev-guest` platform device only when SNP is active in the guest, and
   the driver binds only then: it needs the secrets page and the VM platform
   communication keys that the AMD Secure Processor places in an SNP guest at
   launch. `New` checks with `stat` that the path is a character device and
   that `/sys/class/misc/sev-guest/dev` names the same major and minor
   number. It does not open the device, which is root-only by default, and
   sends it no request.
2. **The configfs-tsm `sev_guest` provider** (`CONFIG_TSM_REPORTS`, Linux 6.7,
   `/sys/kernel/config/tsm/report`). Where the directory exists, `New` creates
   a report entry, reads its `provider` attribute, which must be `sev_guest`,
   and removes the entry. It writes no `inblob` and reads no `outblob`, so no
   report is generated. A TDX guest reads `tdx_guest` here and is refused. A
   kernel without configfs-tsm, or with configfs not mounted, skips this step;
   a refused `mkdir` (`EACCES`, `EPERM`) is a refusal, never a skip.

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
| No `/dev/sev-guest`, or not the `sev-guest` misc device: the host, a plain KVM guest, an SEV or SEV-ES guest without SNP | `*GuestError{Op: "sev-guest", Cause}` matching `ErrSNPGuestUnavailable`; `Cause` the errno (`ENOENT`) or a mismatch |
| The configfs-tsm `provider` is not `sev_guest` | `*GuestError{Op: "tsm-provider", Cause}` matching `ErrSNPGuestUnavailable`; `Cause` names the provider read |
| configfs-tsm present but refused (`EACCES`, `EPERM`) or failing | `*GuestError{Op: "tsm-report", Cause}` matching `ErrSNPGuestUnavailable`; `Cause` the errno |
| Not Linux on amd64 | `ErrSNPGuestUnavailable` with no cause |
| A handle failure (budget, `mlock`, invalid spec) | the root's typed error, unchanged |

`*GuestError` has `Is` and `Unwrap`, so `errors.Is` matches the sentinel and
the errno. A refused `New` returns a nil backend and claims nothing: no
`Confiner` value ever exists outside an SNP guest. A refusal never falls back
to another backend; the program's `Detect` or its own code chooses.

## Test plan

The backend is proven inside a real SEV-SNP guest on an AMD EPYC host with
SEV-SNP (Zen 3 or later). No simulator or emulated platform stands in for it.
QEMU is the VMM driving KVM on that CPU, never TCG. The plan runs as the
self-hosted hardware job, `make integration-test-amd-sev`; unit tests cover
only what touches no device (the device and provider checks against a fake
root directory, error texts and unwrapping).

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
   and the same run as a non-root user gets the `tsm-report` refusal where
   configfs-tsm denies it.
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

The workflow `.github/workflows/amd-sev.yml` runs the target on the
self-hosted runner labelled `amd-sev`, and starts only while the repository
variable `AMD_SEV_RUNNER` is `online`.

## What it does not do

- It does not attest. Evidence of the guest is go-xkms's.
- It does not derive or hold keys; the SNP derived key is go-xkms's.
- It does not isolate inside the guest: the guest kernel, guest root and
  `ptrace` in the guest reach the material as they would outside a CVM.
- It does not protect what the program writes to a socket, disk or console:
  those pass through shared pages the host reads.

## References

- [AMD SEV-SNP firmware ABI specification](https://www.amd.com/en/developer/sev.html)
  (AMD publication 56860): the guest messages and the `SEV_STATUS` MSR.
- Linux `Documentation/virt/coco/sev-guest.rst`: `/dev/sev-guest`.
- Linux `Documentation/ABI/testing/configfs-tsm`: the configfs-tsm report
  interface and its `provider` attribute.
- [confidential-vm proposal](confidential-vm.md): the earlier design, whose
  kernel-interface and threat-model sections still apply.

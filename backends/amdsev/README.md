# backends/amdsev

The go-enclave backend for a process running inside an AMD SEV-SNP guest.
It is its own module and requires a released go-enclave root.

The platform encrypts guest memory against the host, so the whole process
lies inside the trust boundary. The backend's handles are the root package's
locked-memory enclaves; it adds `enclave.Confiner`, whose `ConfinesProcess`
reports true.

```go
a, err := enclave.NewAllocator(1 << 20)
// ...
b, err := amdsev.New(a) // errors.Is(err, amdsev.ErrSNPGuestUnavailable) off SNP
// ...
if err := enclave.Register(b); err != nil {
	// ...
}
```

## Detection

`New` proves SNP from userspace before it returns:

1. `/dev/sev-guest` must open and answer `SNP_GET_REPORT` (requested at
   VMPL 3) with firmware status 0 and a 1184-byte report; else
2. a configfs-tsm entry under `/sys/kernel/config/tsm/report` must name the
   `sev_guest` provider.

A CPUID or `/proc/cpuinfo` flag is never taken as proof. On a host, a plain
VM, or an SEV or SEV-ES guest without SNP, `New` returns a `*GuestError`
matching `ErrSNPGuestUnavailable`; `Op` names the failed step and `Next`
carries the configfs-tsm step's error. The device is root-only by default.

The backend is not an `enclave.Prober`: `Detect` never selects it, and
`main` registers it. Attestation and key protection are not in this module.

## Tests

Unit tests drive every detection branch through an unexported seam and run
`backendtest.TestBackend` on the success seam; no device is needed. The run
inside a real SEV-SNP guest is a separate, hardware job.

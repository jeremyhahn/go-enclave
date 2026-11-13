// Package inteltdx is go-enclave's intel-tdx backend: a process that runs
// inside an Intel TDX trust domain (TD), a confidential virtual machine whose
// memory the host cannot read.
//
// It is pure Go over the TDX guest driver's /dev/tdx_guest ioctl
// (include/uapi/linux/tdx-guest.h, Linux 6.2) and the configfs-tsm report
// interface (/sys/kernel/config/tsm/report, Linux 6.7), so it builds with
// CGO_ENABLED=0. The device code is linux/amd64's; on every other platform
// the package compiles, and [New] and [Backend.Probe] return a
// [*GuestDeviceError] matching [ErrGuestDeviceUnavailable].
//
// Nothing registers at import: main constructs the backend and registers it.
//
//	b, err := inteltdx.New()
//	if err != nil {
//		return err // not in a TD: select another backend
//	}
//	if err := enclave.Register(b); err != nil { ... }
//
// The design, its failure modes and its open questions are
// docs/backends/confidential-vm.md, which replaced the intel-tdx proposal
// this module was built from; the module takes each of that proposal's
// recommended options and names it where the code makes the choice.
package inteltdx

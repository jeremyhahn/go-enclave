// Package confidentialvm is go-enclave's confidential-vm feature: attestation
// for a program inside an AMD SEV-SNP or Intel TDX confidential VM.
//
// A confidential VM is not a backend. The platform encrypts the whole guest
// against the host, so a handle inside it would be ordinary guest memory; the
// program keeps its material in the backends [enclave.Detect] selects, as on
// any host. What the platform adds is evidence about the guest, and this
// package gives it as a standalone [Attester]: [NewAttester] returns a value
// that implements [enclave.Attester] and nothing else of the seam. Its
// evidence is the guest's SNP ATTESTATION_REPORT or TD quote, read through the
// Linux configfs-tsm report interface (/sys/kernel/config/tsm/report).
//
// It is a module of its own: it depends on go-enclave and golang.org/x/sys,
// never the reverse, and importing it registers nothing. On any target other
// than linux/amd64 it compiles, and its constructor refuses with
// [ErrTSMReportUnavailable].
//
// docs/backends/confidential-vm.md is its design.
package confidentialvm

// Package amdsev is the go-enclave backend for a process running inside an
// AMD SEV-SNP guest.
//
// The platform encrypts the guest's memory against the host, so the whole
// process, its heap included, lies inside the trust boundary. The backend's
// handles are the root package's locked-memory enclaves; what it adds is
// [enclave.Confiner]: ConfinesProcess reports true, which lets a Sealer built
// on it run without key-schedule erasure.
//
// [New] proves SNP from userspace before it returns a backend: the guest's
// SEV-SNP device must answer an SNP_GET_REPORT request on /dev/sev-guest, or a
// configfs-tsm report entry must name the sev_guest provider. A CPUID or
// /proc/cpuinfo flag alone is never taken as proof. On a host, a plain VM, or
// an SEV or SEV-ES guest without SNP, New returns an error matching
// [ErrSNPGuestUnavailable].
//
// Attestation and key protection are not in this module.
//
// Importing the package registers nothing; main calls enclave.Register with
// the backend New returns.
package amdsev

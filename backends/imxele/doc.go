// Package imxele is go-enclave's imx-edgelock-enclave backend: keys held in
// the i.MX 95's EdgeLock Enclave, reached through trusted-imx95's trusted
// application over the Linux TEE subsystem (/dev/tee0), in pure Go through
// golang.org/x/sys/unix, without cgo.
//
// The design is docs/backends/imx-edgelock-enclave.md. This module depends on
// go-enclave and golang.org/x/sys only, and registers nothing at import: a
// main registers the backend like any other.
//
// The backend implements [enclave.Backend] and [enclave.Prober]. Its probe
// checks the context, opens the device, checks TEE_IOC_VERSION for a
// GlobalPlatform client, and closes the device, leaving nothing behind (Q4,
// the recommended option). The session and version-command steps refuse with
// [ErrTEESessionUnavailable] until trusted-imx95 publishes its trusted
// application's UUID and command ABI, so the backend never probes usable
// before it can speak to the device. The probe does not refuse an open
// device lifecycle (Q7, the recommended option).
//
// Off Linux the module still compiles: [Connect] and Probe return a
// [*TEEDeviceError] for the "platform" step, matching
// [ErrTEEDeviceUnavailable], with no cause. On Linux the device path is
// tried for real on every architecture, since the TEE ioctl ABI is the same
// on each; a host without the device refuses at the "open" step.
package imxele

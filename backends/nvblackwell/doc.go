// Package nvblackwell is go-enclave's nvidia-blackwell backend: a composing
// backend that adds NVIDIA Blackwell GPUs in confidential computing (CC) mode
// to the CPU TEE backend (intel-tdx or amd-sev) the caller builds and passes
// to [New], as docs/backends/nvidia-blackwell.md proposes.
//
// The design's open questions are answered with its recommended options: a
// composing backend (Q1) given its CPU TEE backend as a constructor argument
// (Q2), ranked inner.Rank()+1 (Q3).
//
// This first slice carries the module, the typed errors of the design's
// "Failure modes", the host probe and the constructor's refusal path. The
// probe checks the NVIDIA open kernel module's procfs entry; the NVML checks
// (GPU architecture, CC mode, DevTools, multi-GPU mode, ready state), Import
// and Attest follow in later slices. Until then [New] refuses every host
// that lacks the driver, which is every host without the hardware.
//
// The backend runs on linux only. On any other platform the module builds,
// and [Probe] and [New] return a [*PlatformError].
//
// Nothing registers at import: main builds the backend with [New] and
// registers it with enclave.Register if it wants detection to see it.
package nvblackwell

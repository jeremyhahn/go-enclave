package nvblackwell

import (
	"errors"
	"strconv"
)

// The errors are the design's "Failure modes" (docs/backends/nvidia-blackwell.md),
// named for the mechanism that failed. Each typed error matches one sentinel
// with errors.Is; go-enclave's own errors are reused where their meaning holds.

// ErrUnsupportedPlatform reports a build for a platform other than linux: the
// backend runs on linux only. Every [PlatformError] matches it.
var ErrUnsupportedPlatform = errors.New("nvblackwell: NVIDIA confidential computing is not available on this platform")

// PlatformError is the error behind [ErrUnsupportedPlatform].
type PlatformError struct {
	// GOOS is the platform the module was built for.
	GOOS string
}

// Error is [ErrUnsupportedPlatform]'s text and the quoted GOOS.
func (e *PlatformError) Error() string {
	return ErrUnsupportedPlatform.Error() + ": " + strconv.Quote(e.GOOS)
}

// Is reports every PlatformError as [ErrUnsupportedPlatform].
func (e *PlatformError) Is(target error) bool { return target == ErrUnsupportedPlatform }

// ErrNVMLUnavailable reports that NVML cannot serve the backend: the NVIDIA
// kernel driver NVML needs is absent or not the open kernel module
// ([DriverError]), libnvidia-ml.so.1 is absent or fails to load, or an NVML
// call returned an error ([NVMLError]).
var ErrNVMLUnavailable = errors.New("nvblackwell: NVML is unavailable")

// DriverError reports the NVIDIA kernel driver's procfs entry missing,
// unreadable, malformed, or naming the proprietary module rather than the
// open kernel module the design requires. It matches [ErrNVMLUnavailable]:
// NVML does not load without the driver. The design's table has no row of
// its own for it; it is named for the mechanism, as the table's are.
type DriverError struct {
	// Path is the procfs file read, such as "/proc/driver/nvidia/version".
	Path string
	// Op is the refused step: "open", "read", "parse" or "open-kernel-module".
	Op string
	// Cause is the refused call's *os.SyscallError wrapping its errno, or nil
	// for "parse" and "open-kernel-module".
	Cause error
}

// Error is [ErrNVMLUnavailable]'s text, the quoted path, the step and the cause.
func (e *DriverError) Error() string {
	msg := ErrNVMLUnavailable.Error() + ": driver " + strconv.Quote(e.Path) + ": " + e.Op
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Is reports every DriverError as [ErrNVMLUnavailable].
func (e *DriverError) Is(target error) bool { return target == ErrNVMLUnavailable }

// Unwrap returns the cause, so errors.Is matches its errno.
func (e *DriverError) Unwrap() error { return e.Cause }

// NVMLError reports an NVML call that failed: libnvidia-ml.so.1 did not load,
// or a call returned an error. It matches [ErrNVMLUnavailable].
type NVMLError struct {
	// Call is the NVML function, such as "nvmlInit_v2", or the load step
	// "load libnvidia-ml.so.1".
	Call string
	// Return is the call's nvmlReturn_t, 0 when the call never returned one.
	Return int
	// Cause is the loader's error, or nil.
	Cause error
}

// Error is [ErrNVMLUnavailable]'s text, the call, its return and the cause.
func (e *NVMLError) Error() string {
	msg := ErrNVMLUnavailable.Error() + ": " + e.Call
	if e.Return != 0 {
		msg += " returned " + strconv.Itoa(e.Return)
	}
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Is reports every NVMLError as [ErrNVMLUnavailable].
func (e *NVMLError) Is(target error) bool { return target == ErrNVMLUnavailable }

// Unwrap returns the cause.
func (e *NVMLError) Unwrap() error { return e.Cause }

// SystemWide is the Device of an error about every GPU at once, such as no
// GPU visible or the system's CC ready state.
const SystemWide = -1

// devicePrefix names a device index, or the system for [SystemWide].
func devicePrefix(device int) string {
	if device == SystemWide {
		return "system"
	}
	return "gpu " + strconv.Itoa(device)
}

// ErrConfComputeUnavailable reports that confidential computing is not usable
// as the backend requires: no GPU visible, CC off, DevTools on, a multi-GPU
// mode not proven on the test hardware, or the ready state not set. Every
// [ConfComputeError] matches it.
var ErrConfComputeUnavailable = errors.New("nvblackwell: GPU confidential computing is not usable")

// ConfComputeError is the error behind [ErrConfComputeUnavailable].
type ConfComputeError struct {
	// Device is the NVML device index, or [SystemWide].
	Device int
	// Setting is the refused setting: "device-count", "cc-mode",
	// "devtools-mode", "multi-gpu-mode" or "ready-state".
	Setting string
	// Value is the value NVML reported.
	Value string
}

// Error is [ErrConfComputeUnavailable]'s text, the device, the setting and
// the quoted value.
func (e *ConfComputeError) Error() string {
	return ErrConfComputeUnavailable.Error() + ": " + devicePrefix(e.Device) + ": " + e.Setting + " is " + strconv.Quote(e.Value)
}

// Is reports every ConfComputeError as [ErrConfComputeUnavailable].
func (e *ConfComputeError) Is(target error) bool { return target == ErrConfComputeUnavailable }

// ErrUnsupportedGPU reports a GPU that is not a Blackwell part. Every
// [GPUArchitectureError] matches it.
var ErrUnsupportedGPU = errors.New("nvblackwell: the GPU is not a Blackwell part")

// GPUArchitectureError is the error behind [ErrUnsupportedGPU].
type GPUArchitectureError struct {
	// Device is the NVML device index.
	Device int
	// Architecture is the nvmlDeviceArchitecture_t NVML reported.
	Architecture uint32
}

// Error is [ErrUnsupportedGPU]'s text, the device and its architecture.
func (e *GPUArchitectureError) Error() string {
	return ErrUnsupportedGPU.Error() + ": " + devicePrefix(e.Device) + ": architecture " +
		strconv.FormatUint(uint64(e.Architecture), 10)
}

// Is reports every GPUArchitectureError as [ErrUnsupportedGPU].
func (e *GPUArchitectureError) Is(target error) bool { return target == ErrUnsupportedGPU }

// ErrGPUAttestation reports that a GPU's attestation report or certificate
// chain could not be fetched. Every [GPUAttestationError] matches it.
var ErrGPUAttestation = errors.New("nvblackwell: the GPU's attestation could not be fetched")

// GPUAttestationError is the error behind [ErrGPUAttestation].
type GPUAttestationError struct {
	// Device is the NVML device index.
	Device int
	// Cause is the failing call's error, such as an [*NVMLError].
	Cause error
}

// Error is [ErrGPUAttestation]'s text, the device and the cause.
func (e *GPUAttestationError) Error() string {
	msg := ErrGPUAttestation.Error() + ": " + devicePrefix(e.Device)
	if e.Cause != nil {
		msg += ": " + e.Cause.Error()
	}
	return msg
}

// Is reports every GPUAttestationError as [ErrGPUAttestation].
func (e *GPUAttestationError) Is(target error) bool { return target == ErrGPUAttestation }

// Unwrap returns the cause.
func (e *GPUAttestationError) Unwrap() error { return e.Cause }

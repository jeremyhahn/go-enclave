package nvblackwell

import "strconv"

// NVML's own values the probe compares against, mirrored from nvml.h so the
// decision builds on every platform (go-nvml's package needs cgo). The cgo
// build of nvml_linux.go fails if any of them drifts from go-nvml's constant.
const (
	// archBlackwell is NVML_DEVICE_ARCH_BLACKWELL.
	archBlackwell uint32 = 10
	// ccFeatureEnabled is NVML_CC_SYSTEM_FEATURE_ENABLED.
	ccFeatureEnabled uint32 = 1
	// devToolsModeOff is NVML_CC_SYSTEM_DEVTOOLS_MODE_OFF.
	devToolsModeOff uint32 = 0
	// multiGPUModeNone is NVML_CC_SYSTEM_MULTIGPU_NONE.
	multiGPUModeNone uint32 = 0
	// multiGPUModeProtectedPCIe is NVML_CC_SYSTEM_MULTIGPU_PROTECTED_PCIE.
	multiGPUModeProtectedPCIe uint32 = 1
	// gpusReadyTrue is NVML_CC_ACCEPTING_CLIENT_REQUESTS_TRUE.
	gpusReadyTrue uint32 = 1
)

// maxGPUs is the most GPUs the probe accepts. Q6, recommended option: only
// the multi-GPU modes proven on the test hardware, single GPU first; none is
// proven yet, so one GPU and no multi-GPU mode.
const maxGPUs = 1

// nvmlSnapshot is what the probe gathers from NVML, in NVML's own values:
// Architectures[i] is nvmlDeviceGetArchitecture of the GPU at NVML index i,
// the CC fields come from nvmlSystemGetConfComputeState and
// nvmlSystemGetConfComputeSettings, and GPUsReady from
// nvmlSystemGetConfComputeGpusReadyState.
type nvmlSnapshot struct {
	Architectures []uint32
	CCFeature     uint32
	DevToolsMode  uint32
	MultiGPUMode  uint32
	GPUsReady     uint32
}

// checkSnapshot decides whether snap is a host the probe accepts: at least
// one GPU, every GPU Blackwell, CC on, DevTools off, no more GPUs and no
// multi-GPU mode beyond what Q6 allows, and the ready state set. The first
// failure, in that order, comes back as its typed error.
func checkSnapshot(snap nvmlSnapshot) error {
	count := len(snap.Architectures)
	if count == 0 {
		return &ConfComputeError{Device: SystemWide, Setting: "GPU count", Value: "0"}
	}
	for i, arch := range snap.Architectures {
		if arch != archBlackwell {
			return &GPUArchitectureError{Device: i, Architecture: arch}
		}
	}
	if snap.CCFeature != ccFeatureEnabled {
		return &ConfComputeError{Device: SystemWide, Setting: "CC feature", Value: nameValue(snap.CCFeature, "disabled", "enabled")}
	}
	if snap.DevToolsMode != devToolsModeOff {
		return &ConfComputeError{Device: SystemWide, Setting: "DevTools mode", Value: nameValue(snap.DevToolsMode, "off", "on")}
	}
	if count > maxGPUs {
		return &ConfComputeError{Device: SystemWide, Setting: "GPU count", Value: strconv.Itoa(count)}
	}
	if snap.MultiGPUMode != multiGPUModeNone {
		return &ConfComputeError{Device: SystemWide, Setting: "multi-GPU mode", Value: nameValue(snap.MultiGPUMode, "none", "protected PCIe")}
	}
	if snap.GPUsReady != gpusReadyTrue {
		return &ConfComputeError{Device: SystemWide, Setting: "GPUs ready state", Value: nameValue(snap.GPUsReady, "not ready", "ready")}
	}
	return nil
}

// nameValue names an NVML value by its index in names, or prints the number
// for a value NVML defines beyond them.
func nameValue(v uint32, names ...string) string {
	if int(v) < len(names) {
		return names[v]
	}
	return strconv.FormatUint(uint64(v), 10)
}

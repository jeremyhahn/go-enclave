//go:build linux && cgo

package nvblackwell

import "github.com/NVIDIA/go-nvml/pkg/nvml"

// The values nvml_check.go mirrors are go-nvml's: a drift makes one of these
// constant indexes overflow or fall out of range, and the build fails.
var (
	_ = [1]struct{}{}[nvml.DEVICE_ARCH_BLACKWELL-archBlackwell]
	_ = [1]struct{}{}[nvml.CC_SYSTEM_FEATURE_ENABLED-ccFeatureEnabled]
	_ = [1]struct{}{}[nvml.CC_SYSTEM_DEVTOOLS_MODE_OFF-devToolsModeOff]
	_ = [1]struct{}{}[nvml.CC_SYSTEM_MULTIGPU_NONE-multiGPUModeNone]
	_ = [1]struct{}{}[nvml.CC_SYSTEM_MULTIGPU_PROTECTED_PCIE-multiGPUModeProtectedPCIe]
	_ = [1]struct{}{}[nvml.CC_ACCEPTING_CLIENT_REQUESTS_TRUE-gpusReadyTrue]
)

// probeNVML loads NVML, gathers the snapshot checkSnapshot decides on, and
// shuts NVML down again whenever Init succeeded. Q5, recommended option:
// go-nvml, NVIDIA's own binding, which loads libnvidia-ml.so.1 at Init.
func probeNVML() error {
	if ret := nvml.Init(); ret != nvml.SUCCESS {
		call := "nvmlInit_v2"
		if ret == nvml.ERROR_LIBRARY_NOT_FOUND {
			call = "load libnvidia-ml.so.1"
		}
		return &NVMLError{Call: call, Return: int(ret)}
	}
	snap, err := gatherNVML()
	if ret := nvml.Shutdown(); ret != nvml.SUCCESS && err == nil {
		err = &NVMLError{Call: "nvmlShutdown", Return: int(ret)}
	}
	if err != nil {
		return err
	}
	return checkSnapshot(snap)
}

// gatherNVML reads every value checkSnapshot needs from an initialized NVML
// and decides nothing; a failed call comes back as an NVMLError naming it.
func gatherNVML() (nvmlSnapshot, error) {
	var snap nvmlSnapshot
	count, ret := nvml.DeviceGetCount()
	if ret != nvml.SUCCESS {
		return snap, &NVMLError{Call: "nvmlDeviceGetCount_v2", Return: int(ret)}
	}
	snap.Architectures = make([]uint32, 0, count)
	for i := range count {
		dev, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return snap, &NVMLError{Call: "nvmlDeviceGetHandleByIndex_v2", Return: int(ret)}
		}
		arch, ret := dev.GetArchitecture()
		if ret != nvml.SUCCESS {
			return snap, &NVMLError{Call: "nvmlDeviceGetArchitecture", Return: int(ret)}
		}
		snap.Architectures = append(snap.Architectures, uint32(arch))
	}
	state, ret := nvml.SystemGetConfComputeState()
	if ret != nvml.SUCCESS {
		return snap, &NVMLError{Call: "nvmlSystemGetConfComputeState", Return: int(ret)}
	}
	snap.CCFeature = state.CcFeature
	snap.DevToolsMode = state.DevToolsMode
	settings, ret := nvml.SystemGetConfComputeSettings()
	if ret != nvml.SUCCESS {
		return snap, &NVMLError{Call: "nvmlSystemGetConfComputeSettings", Return: int(ret)}
	}
	snap.MultiGPUMode = settings.MultiGpuMode
	ready, ret := nvml.SystemGetConfComputeGpusReadyState()
	if ret != nvml.SUCCESS {
		return snap, &NVMLError{Call: "nvmlSystemGetConfComputeGpusReadyState", Return: int(ret)}
	}
	snap.GPUsReady = ready
	return snap, nil
}

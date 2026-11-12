### Added

- The nvidia-blackwell backend's `Probe` now loads NVML through go-nvml after the driver check and refuses unless there is exactly one GPU, it is Blackwell, confidential computing is on, DevTools is off, no multi-GPU mode is set and the GPUs' ready state is set. Each refusal is typed: `*NVMLError` naming the NVML call, `*GPUArchitectureError` naming the GPU, or `*ConfComputeError` naming the setting (#200). A Linux build without cgo refuses with `*NVMLError`. Only the backend module gains the go-nvml dependency; the root module is unchanged.

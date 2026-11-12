### Added

- A new module `backends/nvblackwell` starts the nvidia-blackwell backend (#200): the typed errors of its design's failure modes, a probe that refuses a host without the NVIDIA open kernel module (a `DriverError` naming the failing step and wrapping the errno, or a `PlatformError` off linux), and `New(inner)`, which composes the CPU TEE backend `main` built and refuses one that does not import, attest, probe and confine. The NVML checks, Import and Attest follow. Nothing changes for callers of the root module.

package nvblackwell

// driverVersionPath is the NVIDIA kernel driver's procfs entry, which the
// driver creates when it loads (nv-procfs.c in NVIDIA's open-gpu-kernel-modules).
const driverVersionPath = "/proc/driver/nvidia/version"

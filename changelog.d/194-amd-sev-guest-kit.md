### Added

- A test kit for the amd-sev backend's test plan on the real hardware. `scripts/amdsev-guest.sh` launches an SNP, SEV-ES or plain KVM guest from a pinned local OVMF build and a direct-boot kernel, initrd and command line, with no network device, and exits with the status of the test binary the guest ran; `--dry-run` prints the QEMU command. `scripts/amdsev-host-scan.sh` scans a QEMU process's readable memory on the host for a needle the guest holds. Neither downloads anything. Nothing changes for Go callers.

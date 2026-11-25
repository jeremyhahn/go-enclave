# shellcheck shell=sh
# pins.sh: the pinned inputs of the SEV-SNP guest kit, sourced by
# guest-image.sh and host-record.sh. Each input is pinned by version and by
# the sha256 of the file fetched; a file whose hash differs is refused, never
# used. Bump a pin by changing the version and the hash together, from a file
# you fetched and checked yourself.
#
# The Ubuntu packages come from a dated snapshot of the archive, so a URL
# serves the same bytes for as long as the snapshot exists.

# shellcheck disable=SC2034 # the variables are read by the scripts that source this file
AMDSEV_SNAPSHOT_DEFAULT=https://snapshot.ubuntu.com/ubuntu/20261120T000000Z/pool/main

# OVMF built from OvmfPkg/AmdSev (AmdSevX64.dsc): SEV-SNP support and the
# kernel-hashes table, so the launch measurement covers the direct-boot kernel,
# initrd and command line.
OVMF_VERSION=2026.05-2ubuntu3
OVMF_DEB=e/edk2/ovmf-amdsev_${OVMF_VERSION}_all.deb
OVMF_SHA256=f92fd0aa05f086eeb82d674a21c19c167f49700d6dba76470778c8a763f15552
OVMF_FILE=usr/share/ovmf/OVMF.amdsev.fd

# The direct-boot guest kernel, an SEV-SNP guest kernel (AMD_MEM_ENCRYPT=y,
# TSM_GUEST=y, SEV_GUEST=m, MODULE_DECOMPRESS=y), and its modules package for
# the sev-guest driver and the TSM report interface it registers with.
KERNEL_VERSION=7.3.0-11-generic
KERNEL_PKG_VERSION=7.3.0-11.12
KERNEL_DEB=l/linux/linux-image-unsigned-${KERNEL_VERSION}_${KERNEL_PKG_VERSION}_amd64.deb
KERNEL_SHA256=913514ee6303deef24c4731a09420907ed56872625f5fae51e3d502badbf4f78
KERNEL_FILE=boot/vmlinuz-${KERNEL_VERSION}
MODULES_DEB=l/linux/linux-modules-${KERNEL_VERSION}_${KERNEL_PKG_VERSION}_amd64.deb
MODULES_SHA256=2d7cd11bf31f6b568d9245cbc5af3fb1c750e134abe931b7bdd9a00fe1a90586
# Loaded by the guest's init in this order (each after what it depends on).
MODULES_LOAD="kernel/drivers/virt/coco/guest/tsm_report.ko.zst kernel/drivers/virt/coco/sev-guest/sev-guest.ko.zst"

# QEMU, built from the release tarball: sev-snp-guest with kernel-hashes needs
# 9.1 or later; this is the newest release.
QEMU_VERSION=11.1.3
QEMU_URL_DEFAULT=https://download.qemu.org/qemu-${QEMU_VERSION}.tar.xz
QEMU_SHA256=5a8289c7940dc77d3873c81a6c29ba3afe1446fc9d36e77fa1658cdbecb84b22

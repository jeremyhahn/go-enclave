#!/bin/sh
# host-record.sh: record the SEV-SNP host and refuse one that cannot run the
# kit.
#
# Usage: scripts/amd-sev-snp/host-record.sh
#
# Prints one `key: value` line each for the CPU (vendor, family, model, model
# name), the SNP firmware API version from the kernel log, the host kernel, and
# the QEMU and OVMF versions the kit runs. Then it checks what an SEV-SNP guest
# needs and exits 2 naming every missing piece:
#   - an AMD CPU with the sev_snp flag in /proc/cpuinfo
#   - /dev/kvm
#   - kvm_amd loaded with sev_snp=Y (/sys/module/kvm_amd/parameters/sev_snp)
#   - /dev/sev, the SEV firmware device QEMU opens
# Exit 0 means all are present. Nothing is skipped: a host without SNP fails.
#
# For tests, AMDSEV_ROOT prefixes /proc, /sys and /dev, and AMDSEV_KLOG names a
# file read in place of the kernel log.
set -eu
here=${0%/*}
# shellcheck source=../lib.sh
. "$here/../lib.sh"
# shellcheck source=pins.sh
. "$here/pins.sh"

[ "$#" -eq 0 ] || { echo "$prog: usage: $prog (no arguments)" >&2; exit 2; }

root=${AMDSEV_ROOT:-}
cpuinfo=$root/proc/cpuinfo

field() {
  # the first value of a /proc/cpuinfo field
  while IFS= read -r l; do
    case $l in
      "$1"*:*) v=${l#*:}; printf '%s\n' "${v# }"; return 0 ;;
    esac
  done <"$cpuinfo"
  printf 'unknown\n'
}

klog() {
  if [ -n "${AMDSEV_KLOG:-}" ]; then
    cat -- "$AMDSEV_KLOG" 2>/dev/null || true
  else
    dmesg 2>/dev/null || journalctl -k -b --no-pager 2>/dev/null || true
  fi
}

snp_api() {
  # the ccp driver logs "SEV-SNP API:<major>.<minor> build:<n>" at init
  klog | while IFS= read -r l; do
    case $l in
      *SEV-SNP\ API:*) v=${l#*SEV-SNP API:}; printf '%s\n' "$v"; exit 0 ;;
    esac
  done
}

if [ -r "$cpuinfo" ]; then
  echo "cpu vendor: $(field vendor_id)"
  echo "cpu family: $(field 'cpu family')"
  echo "cpu model: $(field model)"
  echo "cpu model name: $(field 'model name')"
else
  echo "cpu: $cpuinfo is not readable"
fi
api=$(snp_api)
echo "snp firmware api: ${api:-not in the kernel log (unreadable, or the ccp driver did not start SNP)}"
echo "host kernel: $(uname -r)"
if [ -n "${AMDSEV_QEMU:-}" ] && command -v "$AMDSEV_QEMU" >/dev/null 2>&1; then
  echo "qemu: $("$AMDSEV_QEMU" --version 2>/dev/null | { IFS= read -r l || true; printf '%s' "$l"; }) (pinned $QEMU_VERSION)"
else
  echo "qemu: $QEMU_VERSION (pinned, built by guest-image.sh)"
fi
echo "ovmf: ovmf-amdsev $OVMF_VERSION (pinned)"
echo "guest kernel: $KERNEL_VERSION $KERNEL_PKG_VERSION (pinned)"

missing=
miss() { missing="$missing
  - $*"; }

if [ ! -r "$cpuinfo" ]; then
  miss "$cpuinfo: cannot read the CPU flags"
else
  [ "$(field vendor_id)" = AuthenticAMD ] || miss "an AMD CPU: vendor_id is $(field vendor_id), SEV-SNP needs AMD EPYC (Milan or later)"
  case " $(field flags) " in
    *" sev_snp "*) ;;
    *) miss "the sev_snp CPU flag: the CPU lacks SEV-SNP or the BIOS has it off (SEV-SNP, SNP memory coverage, SMEE)" ;;
  esac
fi
[ -e "$root/dev/kvm" ] || miss "/dev/kvm: KVM is not available (kvm_amd not loaded, or virtualization off in the BIOS)"
param=$root/sys/module/kvm_amd/parameters/sev_snp
if [ -r "$param" ]; then
  v=$(cat -- "$param")
  [ "$v" = Y ] || [ "$v" = 1 ] || miss "kvm_amd sev_snp=Y: $param is $v (the host kernel or firmware did not enable SNP)"
else
  miss "kvm_amd sev_snp=Y: $param does not exist (kvm_amd is not loaded, or the host kernel has no SNP host support)"
fi
[ -e "$root/dev/sev" ] || miss "/dev/sev: the SEV firmware device is missing (the ccp driver did not initialise the PSP)"

if [ -n "$missing" ]; then
  echo "$prog: this host cannot run an SEV-SNP guest; missing:$missing" >&2
  exit 2
fi
echo "sev-snp: ready"

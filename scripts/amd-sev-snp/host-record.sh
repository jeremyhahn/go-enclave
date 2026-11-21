#!/bin/sh
# host-record.sh: record the AMD SEV host and refuse one that cannot run the
# kit's guests.
#
# Usage: AMDSEV_GUESTS='sev sev-es' scripts/amd-sev-snp/host-record.sh
#
# AMDSEV_GUESTS lists the encrypted guests the run boots, from sev, sev-es and
# snp (default "sev sev-es"); any other word, or an empty list, exits 2.
# Prints one `key: value` line each for the guests, the CPU (vendor, family,
# model, model name), the SEV and SNP firmware API versions from the kernel
# log, the host kernel, and the QEMU and OVMF versions the kit runs. Then it
# checks what those guests need and exits 2 naming every missing piece:
#   - an AMD CPU, with the sev, sev_es or sev_snp flag in /proc/cpuinfo for
#     each listed guest
#   - /dev/kvm
#   - kvm_amd loaded with sev=Y, sev_es=Y or sev_snp=Y for each listed guest
#     (/sys/module/kvm_amd/parameters/)
#   - /dev/sev, the SEV firmware device QEMU opens
# Exit 0 means all are present. Nothing is skipped: a host without a listed
# guest's support fails.
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

guests=${AMDSEV_GUESTS-sev sev-es}
# shellcheck disable=SC2086 # split the list into words
set -- $guests
[ "$#" -gt 0 ] || { echo "$prog: AMDSEV_GUESTS is empty; list one or more of sev, sev-es, snp" >&2; exit 2; }
for g in "$@"; do
  case $g in
    sev | sev-es | snp) ;;
    *) echo "$prog: AMDSEV_GUESTS names '$g'; want sev, sev-es or snp" >&2; exit 2 ;;
  esac
done
guests=$*

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

api() {
  # the ccp driver logs "SEV API:<major>.<minor> build:<n>" at init, and
  # "SEV-SNP API:..." when it starts SNP
  klog | while IFS= read -r l; do
    case $l in
      *"$1 API:"*) v=${l#*"$1 API:"}; printf '%s\n' "$v"; exit 0 ;;
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
echo "guests: $guests"
v=$(api SEV)
echo "sev firmware api: ${v:-not in the kernel log (unreadable, or the ccp driver did not start SEV)}"
v=$(api SEV-SNP)
echo "snp firmware api: ${v:-not in the kernel log (unreadable, or the ccp driver did not start SNP)}"
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

flag_on() {
  case " $(field flags) " in
    *" $1 "*) return 0 ;;
  esac
  return 1
}

# param NAME WHAT: kvm_amd must be loaded with NAME=Y.
param() {
  p=$root/sys/module/kvm_amd/parameters/$1
  if [ -r "$p" ]; then
    v=$(cat -- "$p")
    [ "$v" = Y ] || [ "$v" = 1 ] || miss "kvm_amd $1=Y: $p is $v (the host kernel or firmware did not enable $2)"
  else
    miss "kvm_amd $1=Y: $p does not exist (kvm_amd is not loaded, or the host kernel has no $2 host support)"
  fi
}

if [ ! -r "$cpuinfo" ]; then
  miss "$cpuinfo: cannot read the CPU flags"
else
  [ "$(field vendor_id)" = AuthenticAMD ] || miss "an AMD CPU: vendor_id is $(field vendor_id), SEV needs AMD EPYC"
fi
[ -e "$root/dev/kvm" ] || miss "/dev/kvm: KVM is not available (kvm_amd not loaded, or virtualization off in the BIOS)"
for g in $guests; do
  case $g in
    sev) f=sev; what=SEV; bios="SEV, SMEE, SEV ASID count" ;;
    sev-es) f=sev_es; what=SEV-ES; bios="SEV-ES ASID space limit above 1" ;;
    snp) f=sev_snp; what=SEV-SNP; bios="SEV-SNP, SNP memory coverage, SMEE" ;;
  esac
  if [ -r "$cpuinfo" ] && ! flag_on "$f"; then
    miss "the $f CPU flag: the CPU lacks $what or the BIOS has it off ($bios)"
  fi
  param "$f" "$what"
done
[ -e "$root/dev/sev" ] || miss "/dev/sev: the SEV firmware device is missing (the ccp driver did not initialise the PSP)"

if [ -n "$missing" ]; then
  echo "$prog: this host cannot run the guests '$guests'; missing:$missing" >&2
  exit 2
fi
echo "amd-sev: ready"

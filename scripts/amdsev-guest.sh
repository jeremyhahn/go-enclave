#!/bin/sh
# amdsev-guest.sh — one guest of the amd-sev test plan on the real hardware.
#
# Usage: scripts/amdsev-guest.sh [--dry-run] [flags] snp|sev-es|plain
#
# Launches one QEMU/KVM guest on the SEV host (docs/backends/amd-sev.md, "Test
# plan on the real hardware", steps 2, 5 and 6) and exits with the status of
# the test binary the guest ran. QEMU drives KVM on the real CPU; nothing the
# backend touches is emulated. The guest boots the pinned OVMF build and a
# direct-boot kernel, initrd and command line, all from local paths: the
# script downloads nothing, and the guest has no network device.
#
#   snp     an SEV-SNP guest: the sev-snp-guest object, policy 0x30000 (debug
#           and migration agent off), kernel-hashes=on, so the launch
#           measurement covers the kernel, initrd and command line
#   sev-es  an SEV-ES guest: the sev-guest object, policy 0x5 (NODBG, ES),
#           kernel-hashes=on (step 6's refusal)
#   plain   a plain KVM guest, no SEV object (step 6's refusal, and step 5's
#           control, where the host scan must find the needle)
#
# Flags (or the environment variable after each):
#   --ovmf PATH      AMDSEV_OVMF     the pinned OVMF build (an AmdSev build for
#                                    kernel-hashes)
#   --kernel PATH    AMDSEV_KERNEL   the direct-boot kernel
#   --initrd PATH    AMDSEV_INITRD   the initrd; its init runs the test binary
#   --append LINE    AMDSEV_APPEND   extra kernel command line, after the
#                                    serial console (default empty)
#   --serial FILE    AMDSEV_SERIAL   the serial console file (default
#                                    ./amdsev-<mode>.serial)
#   --qemu PATH      AMDSEV_QEMU     the VMM (default qemu-system-x86_64)
#   --cpu MODEL      AMDSEV_CPU      the vCPU model (default EPYC-v4)
#   --smp N          AMDSEV_SMP      vCPUs (default 2)
#   --mem SIZE       AMDSEV_MEM      guest RAM (default 2G)
#   --cbitpos N      AMDSEV_CBITPOS  the C-bit position (default 51)
#   --timeout SECS   AMDSEV_TIMEOUT  kill the guest after SECS (default 1800)
#   --dry-run                        print the exact command and exit 0
#
# The initrd's init contract: it runs the test binary as root with its output
# on the serial console (/dev/ttyS0), then prints one line
# `amdsev-guest: exit <status>` and powers the guest off. The script prints the
# console file and exits with <status>; with no such line it fails (exit 2),
# as it does on every error of its own.
#
# A real run refuses unless /dev/kvm exists, and for snp and sev-es also
# /dev/sev.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

fail() { echo "$prog: $*" >&2; exit 2; }

ovmf=${AMDSEV_OVMF:-}
kernel=${AMDSEV_KERNEL:-}
initrd=${AMDSEV_INITRD:-}
append=${AMDSEV_APPEND:-}
serial=${AMDSEV_SERIAL:-}
qemu=${AMDSEV_QEMU:-qemu-system-x86_64}
cpu=${AMDSEV_CPU:-EPYC-v4}
smp=${AMDSEV_SMP:-2}
mem=${AMDSEV_MEM:-2G}
cbitpos=${AMDSEV_CBITPOS:-51}
timeout=${AMDSEV_TIMEOUT:-1800}
dry=
mode=

usage="usage: $prog [--dry-run] [--ovmf PATH --kernel PATH --initrd PATH ...] snp|sev-es|plain"
while [ "$#" -gt 0 ]; do
  case $1 in
    --dry-run) dry=1; shift; continue ;;
    --ovmf | --kernel | --initrd | --append | --serial | --qemu | --cpu | --smp | --mem | --cbitpos | --timeout)
      [ "$#" -ge 2 ] || fail "$1 needs a value; $usage"
      ;;
    -*) fail "unknown flag '$1'; $usage" ;;
    *)
      [ -z "$mode" ] || fail "one mode only; $usage"
      mode=$1; shift; continue
      ;;
  esac
  case $1 in
    --ovmf) ovmf=$2 ;;
    --kernel) kernel=$2 ;;
    --initrd) initrd=$2 ;;
    --append) append=$2 ;;
    --serial) serial=$2 ;;
    --qemu) qemu=$2 ;;
    --cpu) cpu=$2 ;;
    --smp) smp=$2 ;;
    --mem) mem=$2 ;;
    --cbitpos) cbitpos=$2 ;;
    --timeout) timeout=$2 ;;
  esac
  shift 2
done

case $mode in
  snp | sev-es | plain) ;;
  '') fail "$usage" ;;
  *) fail "unknown mode '$mode': want snp, sev-es or plain" ;;
esac
whole() {
  case $2 in
    '' | *[!0-9]*) fail "$1 '$2' is not a whole number" ;;
  esac
}
whole --smp "$smp"
whole --cbitpos "$cbitpos"
whole --timeout "$timeout"
case $mem in
  '' | *[!0-9KMGT]*) fail "--mem '$mem' is not a size such as 2G" ;;
esac
local_file() {
  [ -n "$2" ] || fail "$1 is unset; the kit boots a pinned local image and downloads nothing"
  [ -f "$2" ] || fail "$1 $2 is not a file"
}
local_file --ovmf "$ovmf"
local_file --kernel "$kernel"
local_file --initrd "$initrd"
[ -n "$serial" ] || serial=./amdsev-$mode.serial

# The guest: KVM on the host CPU, no default devices, no network device, the
# serial console in a file, the pinned firmware and the direct-boot image.
machine=q35
set -- -accel kvm -cpu "$cpu" -smp "$smp" -m "$mem" -nodefaults -no-reboot \
  -display none -vga none -monitor none -nic none -serial "file:$serial"
case $mode in
  snp)
    machine=$machine,confidential-guest-support=sev0,memory-backend=ram0
    set -- "$@" -object "memory-backend-memfd,id=ram0,size=$mem,share=true,prealloc=false" \
      -object "sev-snp-guest,id=sev0,cbitpos=$cbitpos,reduced-phys-bits=1,policy=0x30000,kernel-hashes=on"
    ;;
  sev-es)
    machine=$machine,confidential-guest-support=sev0
    set -- "$@" -object "sev-guest,id=sev0,cbitpos=$cbitpos,reduced-phys-bits=1,policy=0x5,kernel-hashes=on"
    ;;
esac
set -- timeout --kill-after=30 "$timeout" "$qemu" -machine "$machine" "$@" \
  -bios "$ovmf" -kernel "$kernel" -initrd "$initrd" \
  -append "console=ttyS0 panic=-1${append:+ $append}"

if [ -n "$dry" ]; then
  line=
  for a in "$@"; do
    case $a in
      *[!A-Za-z0-9_./:=,+@%-]* | '') a="'$(printf '%s' "$a" | tr -d "'")'" ;;
    esac
    line="$line${line:+ }$a"
  done
  printf '%s\n' "$line"
  exit 0
fi

[ -e /dev/kvm ] || fail "/dev/kvm is missing: the guest needs KVM on the host CPU"
if [ "$mode" != plain ]; then
  [ -e /dev/sev ] || fail "/dev/sev is missing: an $mode guest needs the host's SEV firmware (the BIOS settings and kvm_amd sev, sev_es, sev_snp)"
fi
command -v "$qemu" >/dev/null 2>&1 || fail "$qemu: not found"

: >"$serial"
rc=0
"$@" || rc=$?
cat -- "$serial"
[ "$rc" -eq 0 ] || fail "$qemu exited $rc"

marker='amdsev-guest: exit '
cr=$(printf '\r')
status=
while IFS= read -r l || [ -n "$l" ]; do
  case $l in
    "$marker"*) status=${l#"$marker"}; status=${status%"$cr"} ;;
  esac
done <"$serial"
case $status in
  '') fail "no '${marker}<status>' line on the serial console $serial: the guest's init did not finish" ;;
  *[!0-9]*) fail "the guest reported status '$status', not a number" ;;
esac
exit "$status"

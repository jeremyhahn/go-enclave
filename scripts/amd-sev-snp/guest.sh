#!/bin/sh
# guest.sh: boot one fresh guest of the SEV-SNP kit and exit with the status
# of the tests it ran.
#
# Usage: scripts/amd-sev-snp/guest.sh [--dry-run] [flags] snp|plain
#
#   snp    an SEV-SNP guest: the sev-snp-guest object with policy 0x30000
#          (debug off, migration agent off, SMT allowed) and kernel-hashes=on,
#          so the launch measurement covers the kernel, initrd and command line
#   plain  the same image as a plain KVM guest, no SEV object: the refusal
#          case, and the control in which the host scan must find the needle
#
# Flags (or the environment variable after each):
#   --kit DIR        AMDSEV_KIT      the kit guest-image.sh built (default
#                                    ~/.cache/go-enclave/amd-sev-snp/kit); the
#                                    four paths below default to files in it
#   --ovmf PATH      AMDSEV_OVMF     the pinned OVMF.amdsev.fd
#   --kernel PATH    AMDSEV_KERNEL   the direct-boot kernel
#   --initrd PATH    AMDSEV_INITRD   the initrd; its /init runs the tests
#   --qemu PATH      AMDSEV_QEMU     the pinned QEMU build
#   --append LINE    AMDSEV_APPEND   more kernel command line (amdsev.run=...)
#   --serial FILE    AMDSEV_SERIAL   the console file (default ./amdsev-<mode>.serial)
#   --pidfile FILE   AMDSEV_PIDFILE  where QEMU writes its pid (for the host scan)
#   --cpu MODEL      AMDSEV_CPU      the vCPU model (default EPYC-v4)
#   --smp N          AMDSEV_SMP      vCPUs (default 2)
#   --mem SIZE       AMDSEV_MEM      guest RAM (default 2G)
#   --cbitpos N      AMDSEV_CBITPOS  the C-bit position (default 51)
#   --timeout SECS   AMDSEV_TIMEOUT  kill the guest after SECS (default 1800)
#   --dry-run                        print the QEMU command and exit 0
#
# The guest has no network device and no disk; the kernel command line carries
# amdsev.mode=<mode>. The init contract (test/integration/amdsev/guestinit):
# the tests run as root with their output on ttyS0, then one line
# `amdsev-guest: exit <status>`, then power off. The script prints the console
# and exits with <status>; without that line, or on its own errors, it exits 2.
# A real run refuses unless /dev/kvm exists, and for snp also /dev/sev.
set -eu
# shellcheck source=../lib.sh
. "${0%/*}/../lib.sh"

fail() { echo "$prog: $*" >&2; exit 2; }

kit=${AMDSEV_KIT:-${HOME:-/nonexistent}/.cache/go-enclave/amd-sev-snp/kit}
ovmf=${AMDSEV_OVMF:-}
kernel=${AMDSEV_KERNEL:-}
initrd=${AMDSEV_INITRD:-}
qemu=${AMDSEV_QEMU:-}
append=${AMDSEV_APPEND:-}
serial=${AMDSEV_SERIAL:-}
pidfile=${AMDSEV_PIDFILE:-}
cpu=${AMDSEV_CPU:-EPYC-v4}
smp=${AMDSEV_SMP:-2}
mem=${AMDSEV_MEM:-2G}
cbitpos=${AMDSEV_CBITPOS:-51}
timeout=${AMDSEV_TIMEOUT:-1800}
dry=
mode=

usage="usage: $prog [--dry-run] [--kit DIR ...] snp|plain"
while [ "$#" -gt 0 ]; do
  case $1 in
    --dry-run) dry=1; shift; continue ;;
    --kit | --ovmf | --kernel | --initrd | --qemu | --append | --serial | --pidfile | --cpu | --smp | --mem | --cbitpos | --timeout)
      [ "$#" -ge 2 ] || fail "$1 needs a value; $usage"
      ;;
    -*) fail "unknown flag '$1'; $usage" ;;
    *)
      [ -z "$mode" ] || fail "one mode only; $usage"
      mode=$1; shift; continue
      ;;
  esac
  case $1 in
    --kit) kit=$2 ;;
    --ovmf) ovmf=$2 ;;
    --kernel) kernel=$2 ;;
    --initrd) initrd=$2 ;;
    --qemu) qemu=$2 ;;
    --append) append=$2 ;;
    --serial) serial=$2 ;;
    --pidfile) pidfile=$2 ;;
    --cpu) cpu=$2 ;;
    --smp) smp=$2 ;;
    --mem) mem=$2 ;;
    --cbitpos) cbitpos=$2 ;;
    --timeout) timeout=$2 ;;
  esac
  shift 2
done

case $mode in
  snp | plain) ;;
  '') fail "$usage" ;;
  *) fail "unknown mode '$mode': want snp or plain" ;;
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
[ -n "$ovmf" ] || ovmf=$kit/OVMF.amdsev.fd
[ -n "$kernel" ] || kernel=$kit/vmlinuz
[ -n "$initrd" ] || initrd=$kit/initrd.img
[ -n "$qemu" ] || qemu=$kit/qemu-system-x86_64
local_file() {
  [ -f "$2" ] || fail "$1 $2 is not a file; build the kit with scripts/amd-sev-snp/guest-image.sh"
}
local_file --ovmf "$ovmf"
local_file --kernel "$kernel"
local_file --initrd "$initrd"
[ -n "$serial" ] || serial=./amdsev-$mode.serial

# KVM on the host CPU, no default devices, no network, no disk, the console in
# a file, the pinned firmware and the direct-boot image.
machine=q35
set -- -accel kvm -cpu "$cpu" -smp "$smp" -m "$mem" -nodefaults -no-reboot \
  -display none -vga none -monitor none -nic none -serial "file:$serial"
[ -z "$pidfile" ] || set -- "$@" -pidfile "$pidfile"
if [ "$mode" = snp ]; then
  machine=$machine,confidential-guest-support=sev0,memory-backend=ram0
  set -- "$@" -object "memory-backend-memfd,id=ram0,size=$mem,share=true,prealloc=false" \
    -object "sev-snp-guest,id=sev0,cbitpos=$cbitpos,reduced-phys-bits=1,policy=0x30000,kernel-hashes=on"
fi
set -- timeout --kill-after=30 "$timeout" "$qemu" -machine "$machine" "$@" \
  -bios "$ovmf" -kernel "$kernel" -initrd "$initrd" \
  -append "console=ttyS0 panic=-1 amdsev.mode=$mode${append:+ $append}"

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
if [ "$mode" = snp ]; then
  [ -e /dev/sev ] || fail "/dev/sev is missing: an SEV-SNP guest needs the host's SEV firmware (BIOS SEV-SNP on, kvm_amd sev_snp=Y)"
fi
[ -x "$qemu" ] || fail "$qemu: not an executable; build the kit with scripts/amd-sev-snp/guest-image.sh"

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
  '') fail "no '${marker}<status>' line on the console $serial: the guest's init did not finish" ;;
  *[!0-9]*) fail "the guest reported status '$status', not a number" ;;
esac
exit "$status"

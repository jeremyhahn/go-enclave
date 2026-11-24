#!/bin/sh
# host-scan.sh: scan a guest's QEMU process, from the host, for a needle.
#
# Usage: scripts/amd-sev-snp/host-scan.sh <qemu-pid> <hex-needle>   (as root)
#
# Reads every readable mapping in /proc/<pid>/maps through /proc/<pid>/mem,
# the scan internal/memscan does in-process, done here across the process
# boundary. In an SEV-SNP guest the needle the guest holds must not be found;
# in the plain KVM control of the same image it must be. Exits 0 when the
# needle is not found, 1 when it is (naming each mapping), 2 on an error,
# including when no mapping could be read.
#
# The scan is backends/amdsev/integration/cmd/amdsev-hostscan: the script runs
# $AMDSEV_HOSTSCAN when it is set, and otherwise builds the helper from this
# tree with the module proxy off, so it downloads nothing.
set -eu
here=${0%/*}
# shellcheck source=../lib.sh
. "$here/../lib.sh"

fail() { echo "$prog: $*" >&2; exit 2; }

[ "$#" -eq 2 ] || fail "usage: $prog <qemu-pid> <hex-needle>"
pid=$1
needle=$2
case $pid in
  '' | *[!0-9]*) fail "pid '$pid' is not a process id" ;;
esac
case $needle in
  '' | *[!0-9a-fA-F]*) fail "the needle is not a hex string" ;;
esac
[ $((${#needle} % 2)) -eq 0 ] || fail "the needle has an odd number of hex digits"
[ -r "/proc/$pid/maps" ] || fail "no readable /proc/$pid/maps: no such process, or not root"

helper=${AMDSEV_HOSTSCAN:-}
if [ -z "$helper" ]; then
  module=$(cd "$here/../../backends/amdsev/integration" && pwd)
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  helper=$tmp/amdsev-hostscan
  (cd "$module" && GOWORK=off GOPROXY=off GOFLAGS=-mod=readonly go build -o "$helper" ./cmd/amdsev-hostscan) ||
    fail "cannot build backends/amdsev/integration/cmd/amdsev-hostscan"
fi
rc=0
"$helper" "$pid" "$needle" || rc=$?
exit "$rc"

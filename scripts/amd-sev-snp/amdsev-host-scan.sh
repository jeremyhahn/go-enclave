#!/bin/sh
# amdsev-host-scan.sh — the host-side scan of the amd-sev test plan, item 4.
#
# Usage: scripts/amd-sev-snp/amdsev-host-scan.sh <qemu-pid> <hex-needle>   (as root)
#
# Scans the readable ranges of /proc/<pid>/maps through /proc/<pid>/mem for
# the needle the guest holds (docs/backends/amd-sev-snp.md, "Test plan",
# item 4): in an SNP guest it must not be found; in the plain KVM control it
# must be. Exits 0 when the needle is not found, 1 when it is found, 2 on an
# error. The scan is backends/amdsev/integration/cmd/amdsev-hostscan, the
# scanner host-scan.sh runs: the script runs $AMDSEV_HOSTSCAN when it is set,
# and otherwise builds the helper from this tree with the module proxy off,
# so it downloads nothing.
set -eu
# shellcheck source=../lib.sh
. "${0%/*}/../lib.sh"

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
  module=$(cd "${0%/*}/../../backends/amdsev/integration" && pwd)
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  helper=$tmp/amdsev-hostscan
  (cd "$module" && GOWORK=off GOPROXY=off GOFLAGS=-mod=readonly go build -o "$helper" ./cmd/amdsev-hostscan) ||
    fail "cannot build backends/amdsev/integration/cmd/amdsev-hostscan"
fi
rc=0
"$helper" "$pid" "$needle" || rc=$?
exit "$rc"

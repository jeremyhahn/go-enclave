#!/bin/sh
# run.sh: the AMD SEV hardware run behind make integration-test-amd-sev.
#
# Usage: AMDSEV_GUESTS='sev sev-es' scripts/amd-sev-snp/run.sh
#
# AMDSEV_GUESTS lists the encrypted guests to boot, from sev, sev-es and snp
# (default "sev sev-es"); the plain KVM control always boots too.
#
#   1. host-record.sh: record the host, and fail naming what is missing when
#      it cannot run the listed guests
#   2. the kit's own tests, which need no hardware (the host-scan logic
#      against a local process, the guest init, the scripts' argument handling)
#   3. guest-image.sh: the guest kit from the pinned inputs
#   4. the host tests of backends/amdsev/integration (TestAmdSev_Host...), as
#      root: the backend's refusal on the host, then a fresh guest for each
#      listed mode and a fresh plain KVM guest of the same image, each running
#      its in-guest tests (backendtest in SNP, the refusal in SEV, SEV-ES and
#      plain KVM, the held needle in all), with the host scan of each guest's
#      QEMU process
#
# The consoles and the host record land in $AMDSEV_RESULTS (default
# $AMDSEV_CACHE/results), emptied at the start of each run. Step 4 runs under
# sudo -n when the caller is not root: reading another process's memory and
# opening /dev/sev need it. Nothing is skipped; each missing piece fails the
# run with its name.
set -eu
here=$(cd "${0%/*}" && pwd)
# shellcheck source=../lib.sh
. "$here/../lib.sh"

fail() { echo "$prog: $*" >&2; exit 2; }

[ "$#" -eq 0 ] || fail "usage: $prog (no arguments; see the AMDSEV_ variables in the scripts)"

module=$(cd "$here/../../backends/amdsev/integration" && pwd)
cache=${AMDSEV_CACHE:-${HOME:-/nonexistent}/.cache/go-enclave/amd-sev-snp}
# Absolute: step 4 runs from $results and is handed paths under the cache.
mkdir -p "$cache"
cache=$(cd "$cache" && pwd)
results=${AMDSEV_RESULTS:-$cache/results}
export AMDSEV_CACHE="$cache"

mkdir -p "$results"
rm -f -- "$results"/*
guests=${AMDSEV_GUESTS-sev sev-es}
AMDSEV_GUESTS=$guests sh "$here/host-record.sh" >"$results/host-record.txt" 2>&1 || {
  cat -- "$results/host-record.txt" >&2
  fail "step 1, the host record, failed: this host cannot run the guests '$guests'"
}
cat -- "$results/host-record.txt"

command -v go >/dev/null 2>&1 || fail "go: not found; the kit builds its tests with the Go toolchain backends/amdsev/go.mod names"
(cd "$module" && GOWORK=off go test -count=1 ./guestcfg/... ./hostscan/... ./cmd/... ./guestinit/... ./kittest/...) ||
  fail "step 2, the kit's own tests, failed"

sh "$here/guest-image.sh" all || fail "step 3, the guest kit, failed"

bin=$cache/amdsev-host.test
(cd "$module" && GOWORK=off CGO_ENABLED=0 go test -c -tags amdsev -o "$bin" .) || fail "cannot build the host test binary"
# The scanner is built here, not by host-scan.sh: step 4 may run under sudo,
# whose secure_path need not hold go.
scanner=$cache/amdsev-hostscan
(cd "$module" && GOWORK=off CGO_ENABLED=0 go build -o "$scanner" ./cmd/amdsev-hostscan) || fail "cannot build the host scanner"
set -- env AMDSEV_KIT="$cache/kit" AMDSEV_RESULTS="$results" AMDSEV_SCRIPTS="$here" AMDSEV_HOSTSCAN="$scanner" AMDSEV_GUESTS="$guests" \
  "$bin" -test.run '^TestAmdSev_Host' -test.v -test.count=1 -test.timeout=80m
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || fail "not root and no sudo: the host scan reads QEMU's memory and needs root"
  set -- sudo -n -- "$@"
fi
(cd "$results" && "$@") || fail "step 4, the guest tests and the host scan, failed; the consoles are in $results"

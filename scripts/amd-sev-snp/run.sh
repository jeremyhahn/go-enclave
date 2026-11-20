#!/bin/sh
# run.sh: the SEV-SNP hardware run behind make integration-test-amd-sev.
#
# Usage: scripts/amd-sev-snp/run.sh
#
#   1. host-record.sh: record the host, and fail naming what is missing when
#      it cannot run an SEV-SNP guest
#   2. the kit's own tests, which need no hardware (the host-scan logic
#      against a local process, the guest init, the scripts' argument handling)
#   3. guest-image.sh: the guest kit from the pinned inputs
#   4. the host tests of test/integration/amdsev (TestAmdSev_Host...), as
#      root: the backend's refusal on the host, then a fresh SEV-SNP guest and a
#      fresh plain KVM guest of the same image, each running its in-guest tests
#      (backendtest in SNP, the refusal in plain KVM, the held needle in both),
#      with the host scan of each guest's QEMU process
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

module=$(cd "$here/../../test/integration/amdsev" && pwd)
cache=${AMDSEV_CACHE:-${HOME:-/nonexistent}/.cache/go-enclave/amd-sev-snp}
results=${AMDSEV_RESULTS:-$cache/results}
export AMDSEV_CACHE="$cache"

mkdir -p "$results"
rm -f -- "$results"/*
sh "$here/host-record.sh" >"$results/host-record.txt" 2>&1 || {
  cat -- "$results/host-record.txt" >&2
  fail "step 1, the host record, failed: this host cannot run the SEV-SNP tests"
}
cat -- "$results/host-record.txt"

command -v go >/dev/null 2>&1 || fail "go: not found; the kit builds its tests with the Go toolchain test/integration/amdsev/go.mod names"
(cd "$module" && GOWORK=off go test -count=1 ./guestcfg/... ./hostscan/... ./cmd/... ./guestinit/... ./kittest/...) ||
  fail "step 2, the kit's own tests, failed"

sh "$here/guest-image.sh" all || fail "step 3, the guest kit, failed"

bin=$cache/amdsev-host.test
(cd "$module" && GOWORK=off CGO_ENABLED=0 go test -c -o "$bin" .) || fail "cannot build the host test binary"
set -- env AMDSEV_KIT="$cache/kit" AMDSEV_RESULTS="$results" AMDSEV_SCRIPTS="$here" \
  "$bin" -test.run '^TestAmdSev_Host' -test.v -test.count=1 -test.timeout=80m
if [ "$(id -u)" -ne 0 ]; then
  command -v sudo >/dev/null 2>&1 || fail "not root and no sudo: the host scan reads QEMU's memory and needs root"
  set -- sudo -n -- "$@"
fi
(cd "$results" && "$@") || fail "step 4, the SEV-SNP guest tests and the host scan, failed; the consoles are in $results"

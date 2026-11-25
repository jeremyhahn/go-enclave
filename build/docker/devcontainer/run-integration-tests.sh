#!/bin/sh
# run-integration-tests.sh <package> runs one integration suite with library coverage from every process and enforces the per-package floor.
set -eu

# Every refusal exits 2. (${VAR:?} would leave the status to the shell:
# 2 in dash, 1 in bash as sh.)
refuse() { echo "run-integration-tests: $*" >&2; exit 2; }
required() { eval "[ -n \"\${$1:-}\" ]" || refuse "$1 is required"; }
pkg=${1-}
[ -n "$pkg" ] || refuse "usage: run-integration-tests.sh <package>"
case $pkg in
  *[!a-z0-9_-]*) refuse "invalid package name" ;;
esac
required GO_ENCLAVE_IT_COVERAGE_FLOOR
required GO_ENCLAVE_IT_COVERPKG
required GO_ENCLAVE_IT_TESTFLAGS
floor=$GO_ENCLAVE_IT_COVERAGE_FLOOR
# N or N.N...: digits, then at most one dot with digits on both sides.
case $floor in
  ''|.*|*.|*.*.*|*[!0-9.]*) refuse "invalid coverage floor" ;;
esac
coverpkg=$GO_ENCLAVE_IT_COVERPKG
flags=$GO_ENCLAVE_IT_TESTFLAGS

dir=test/integration/$pkg
[ -d "$dir" ] || refuse "$dir does not exist"

covdir=$(mktemp -d /tmp/covdata.XXXXXX)
trap 'rm -rf "$covdir"' EXIT

# $flags is a word list by design (operator-chosen go test flags).
# shellcheck disable=SC2086
GOCOVERDIR=$covdir go test $flags -cover -coverpkg="$coverpkg" "./$dir" -args -test.gocoverdir="$covdir"

# One merged profile drives the gate, compared on exact statement counts.
profile=$(mktemp /tmp/profile.XXXXXX)
trap 'rm -rf "$covdir" "$profile"' EXIT
go tool covdata textfmt -i="$covdir" -pkg="$coverpkg" -o "$profile"

# GO_ENCLAVE_IT_PROFILE_OUT copies the merged profile to a path, or prints it between markers for "-".
if [ "${GO_ENCLAVE_IT_PROFILE_OUT:-}" = "-" ]; then
  echo "BEGIN GO_ENCLAVE_IT_PROFILE"
  cat "$profile"
  echo "END GO_ENCLAVE_IT_PROFILE"
elif [ -n "${GO_ENCLAVE_IT_PROFILE_OUT:-}" ]; then
  cp "$profile" "$GO_ENCLAVE_IT_PROFILE_OUT"
fi

# Every instrumented package must appear in the profile: a package missing
# from it was never exercised, which is 0%, not "not applicable".
status=0
old_ifs=$IFS; IFS=,
# $coverpkg is a comma-separated list by design.
# shellcheck disable=SC2086
set -- $coverpkg
IFS=$old_ifs
sh "$(dirname -- "$0")/../../../scripts/coverage-gate.sh" "$floor" "$profile" "$@" || status=$?
if [ "$status" -ne 0 ]; then
  # List the least-covered functions.
  echo "Least-covered functions (integration):" >&2
  go tool cover -func="$profile" | grep -v '^total:' | awk '{ pct = $NF; sub("%", "", pct); if (pct + 0 < 100) print }' | sort -k3 -n | head -60 >&2
fi
exit $status

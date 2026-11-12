#!/bin/sh
# run-integration-tests.sh <package> — the devcontainer side of
# `make integration-test-<package>` (testing-guidelines: "ALWAYS make sure ALL
# packages have at least 90% integration test coverage").
#
# Runs one integration suite with the LIBRARY instrumented for coverage, then
# fails unless every library package reaches the floor. Coverage is collected
# from the parent test process AND from every child it re-executes (see
# test/integration/enclave/isolation_test.go): the binary is built with -cover,
# GOCOVERDIR names a directory every process writes its counters into on exit,
# and the harness hands the same directory to each child. A child that wrote
# nothing would simply under-count, which can only make the gate stricter.
#
# Environment (set by the Makefile through `docker compose run -e`):
#   GO_ENCLAVE_IT_TESTFLAGS        go test flags (tags, -race, -count, -v, timeout)
#   GO_ENCLAVE_IT_COVERAGE_FLOOR   per-package floor, percent (integer or decimal)
#   GO_ENCLAVE_IT_COVERPKG         comma-separated import paths to instrument
#   GO_ENCLAVE_IT_PROFILE_OUT      optional: write the merged profile here
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

# One merged profile, written outside the covdata directory, is the source of
# both the gate and anything printed: per-block statement counts, so the floor
# is compared on exact covered/total statements. (`covdata percent` rounds to
# one decimal first, which would pass 89.96% as 90.0%.)
profile=$(mktemp /tmp/profile.XXXXXX)
trap 'rm -rf "$covdir" "$profile"' EXIT
go tool covdata textfmt -i="$covdir" -pkg="$coverpkg" -o "$profile"

# For whoever is raising coverage: GO_ENCLAVE_IT_PROFILE_OUT names a path to
# copy the merged profile to (cover -func / -html format), or "-" to print it
# between BEGIN/END marker lines — the container's filesystem is read-only, so
# "-" is how `make integration-test GO_ENCLAVE_IT_PROFILE_OUT=-` gets it to the
# host. The gate below does not depend on it.
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
  # Say WHERE the suite falls short, not only by how much: the least-covered
  # functions of the instrumented packages, from the same profile.
  echo "Least-covered functions (integration):" >&2
  go tool cover -func="$profile" | grep -v '^total:' | awk '{ pct = $NF; sub("%", "", pct); if (pct + 0 < 100) print }' | sort -k3 -n | head -60 >&2
fi
exit $status

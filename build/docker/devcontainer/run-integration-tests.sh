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

pkg=${1:?usage: run-integration-tests.sh <package>}
case $pkg in
  ''|*[!a-z0-9_-]*) echo "run-integration-tests: invalid package name" >&2; exit 2 ;;
esac
floor=${GO_ENCLAVE_IT_COVERAGE_FLOOR:?GO_ENCLAVE_IT_COVERAGE_FLOOR is required}
case $floor in
  ''|*[!0-9.]*) echo "run-integration-tests: invalid coverage floor" >&2; exit 2 ;;
esac
coverpkg=${GO_ENCLAVE_IT_COVERPKG:?GO_ENCLAVE_IT_COVERPKG is required}
flags=${GO_ENCLAVE_IT_TESTFLAGS:?GO_ENCLAVE_IT_TESTFLAGS is required}

dir=test/integration/$pkg
[ -d "$dir" ] || { echo "run-integration-tests: $dir does not exist" >&2; exit 2; }

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
for want in $coverpkg; do
  IFS=$old_ifs
  # Blocks are keyed by file:range and counted once (the larger count wins,
  # should a block appear twice); a block's package is its file's directory.
  counts=$(awk -v p="$want" '
    NR == 1 && /^mode:/ { next }
    {
      split($1, loc, ":"); file = loc[1]
      pkg = file; sub("/[^/]*$", "", pkg)
      if (pkg != p) next
      if (!($1 in n)) { n[$1] = $2; c[$1] = $3 } else if ($3 > c[$1]) c[$1] = $3
    }
    END {
      for (k in n) { total += n[k]; if (c[k] > 0) covered += n[k] }
      printf "%d %d\n", covered, total
    }' "$profile")
  covered=${counts% *}; total=${counts#* }
  if [ "$total" -eq 0 ]; then
    echo "FAIL: $want has no integration coverage at all" >&2
    status=1
    continue
  fi
  pct=$(awk -v c="$covered" -v t="$total" 'BEGIN { printf "%.2f", 100 * c / t }')
  printf '\t%s\t\tcoverage: %s%% of statements (%d of %d)\n' "$want" "$pct" "$covered" "$total"
  if ! awk -v c="$covered" -v t="$total" -v f="$floor" 'BEGIN { exit !(100 * c >= f * t) }'; then
    echo "FAIL: $want integration coverage $pct% ($covered of $total statements) is below the $floor% floor" >&2
    status=1
  fi
done
IFS=$old_ifs
if [ "$status" -ne 0 ]; then
  # Say WHERE the suite falls short, not only by how much: the least-covered
  # functions of the instrumented packages, from the same profile.
  echo "Least-covered functions (integration):" >&2
  go tool cover -func="$profile" | grep -v '^total:' | awk '{ pct = $NF; sub("%", "", pct); if (pct + 0 < 100) print }' | sort -k3 -n | head -60 >&2
fi
exit $status

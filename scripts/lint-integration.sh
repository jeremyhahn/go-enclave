#!/bin/sh
# lint-integration.sh — prove the integration build tag selects the suite's files.
#
# Usage: scripts/lint-integration.sh <package>...   (from the repository root)
#
# `make lint` runs without the integration tag and never sees the suite, so
# `make lint-integration` first proves, per package, that the tag selects test
# files and that nothing in test/integration/<package> builds without it.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

go=${GOCMD:-go}
for p in "$@"; do
  with=$("$go" list -tags=integration -f '{{len .TestGoFiles}}{{len .XTestGoFiles}}' "./test/integration/$p")
  without=$("$go" list -e -f '{{len .TestGoFiles}}{{len .XTestGoFiles}}' "./test/integration/$p" 2>/dev/null) || true
  case $with in 00|'') die "-tags=integration selects no test files in test/integration/$p" ;; esac
  case $without in 00|'') ;; *) die "test/integration/$p has test files that build WITHOUT the integration tag ($without)" ;; esac
done

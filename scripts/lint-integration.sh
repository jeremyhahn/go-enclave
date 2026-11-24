#!/bin/sh
# lint-integration.sh <package>...: proves the integration tag selects each suite's files and nothing there builds without it.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

go=${GOCMD:-go}
# With no package there is nothing to prove: a usage error, not a pass.
[ $# -gt 0 ] || die "usage: $0 <package>..."
for p in "$@"; do
  with=$("$go" list -tags=integration -f '{{len .TestGoFiles}}{{len .XTestGoFiles}}' "./test/integration/$p")
  without=$("$go" list -e -f '{{len .TestGoFiles}}{{len .XTestGoFiles}}' "./test/integration/$p" 2>/dev/null) || true
  case $with in 00|'') die "-tags=integration selects no test files in test/integration/$p" ;; esac
  case $without in 00|'') ;; *) die "test/integration/$p has test files that build WITHOUT the integration tag ($without)" ;; esac
done

#!/bin/sh
# cross-build.sh — compile (and vet) every package for each GOOS/GOARCH given.
#
# Usage: scripts/cross-build.sh <goos/goarch>... -- <package>...
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

go=${GOCMD:-go}
targets=
while [ $# -gt 0 ] && [ "$1" != -- ]; do
  targets="$targets $1"
  shift
done
[ $# -gt 0 ] || die "usage: $0 <goos/goarch>... -- <package>..."
shift

for t in $targets; do
  echo "$prog $t"
  GOOS=${t%/*} GOARCH=${t#*/} "$go" build "$@"
  GOOS=${t%/*} GOARCH=${t#*/} "$go" vet "$@"
done

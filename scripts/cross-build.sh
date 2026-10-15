#!/bin/sh
# cross-build.sh — compile, vet and link the test binaries of every
# package for each GOOS/GOARCH given. No test runs: linking catches what vet
# cannot (a test file that compiles nowhere but on the host).
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

# go test -c writes one binary per package into a directory -o names.
testbin=$(mktemp -d)
trap 'rm -rf "$testbin"' EXIT

for t in $targets; do
  echo "$prog $t"
  GOOS=${t%/*} GOARCH=${t#*/} "$go" build "$@"
  GOOS=${t%/*} GOARCH=${t#*/} "$go" vet "$@"
  GOOS=${t%/*} GOARCH=${t#*/} "$go" test -c -o "$testbin/" "$@"
done

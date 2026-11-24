#!/bin/sh
# cross-build.sh <goos/goarch>... -- <package>...: compile, vet and link test binaries per target with cgo off.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

go=${GOCMD:-go}
CGO_ENABLED=0
export CGO_ENABLED
targets=
while [ $# -gt 0 ] && [ "$1" != -- ]; do
  targets="$targets $1"
  shift
done
# With no target or no package there is nothing to check: a usage error, not a pass.
[ $# -gt 1 ] && [ -n "$targets" ] || die "usage: $0 <goos/goarch>... -- <package>..."
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

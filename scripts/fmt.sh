#!/bin/sh
# fmt.sh — gofmt from the module's own toolchain.
#
# Usage: scripts/fmt.sh write|check   (from the repository root)
#
# check lists the unformatted files and fails; it changes nothing.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

gofmt=$("${GOCMD:-go}" env GOROOT)/bin/gofmt
case ${1-} in
  write) exec "$gofmt" -w . ;;
  check)
    unformatted=$("$gofmt" -l .)
    [ -z "$unformatted" ] || { echo "Not formatted:"; echo "$unformatted"; exit 1; }
    ;;
  *) die "usage: $0 write|check" ;;
esac

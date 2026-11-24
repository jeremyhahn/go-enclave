#!/bin/sh
# fmt.sh write|check: gofmt from the module's own toolchain.
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

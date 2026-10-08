#!/bin/sh
# deps-latest.sh — bump internal dependencies to their latest tags, then tidy.
#
# Usage: scripts/deps-latest.sh   (from the repository root)
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

go=${GOCMD:-go}
GOWORK=off
export GOWORK
self=$("$go" list -m)
for m in $("$go" list -m -f '{{if not .Indirect}}{{.Path}}{{end}}' all 2>/dev/null | grep '^github.com/jeremyhahn/' | grep -vx "$self" || true); do
  v=$("$go" list -m -versions "$m" 2>/dev/null | tr ' ' '\n' | tail -n 1)
  if [ -n "$v" ] && [ "$v" != "$m" ]; then "$go" get "$m@$v"; fi
done
"$go" mod tidy

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
mods=$("$go" list -m -f '{{if not .Indirect}}{{.Path}}{{end}}' all) || die "go list -m all failed"
for m in $(printf '%s\n' "$mods" | grep '^github.com/jeremyhahn/' | grep -vx "$self" || true); do
  versions=$("$go" list -m -versions "$m") || die "go list -m -versions $m failed"
  v=$(printf '%s\n' "$versions" | tr ' ' '\n' | tail -n 1)
  if [ -n "$v" ] && [ "$v" != "$m" ]; then "$go" get "$m@$v"; fi
done
"$go" mod tidy

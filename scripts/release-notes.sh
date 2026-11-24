#!/bin/sh
# release-notes.sh <vX.Y.Z[-pre]> [CHANGELOG.md]: print exactly one non-empty version section, without footer links.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

case $# in 1|2) ;; *) die "usage: $0 <vX.Y.Z[-pre]> [CHANGELOG.md]" ;; esac
version=$1
changelog=${2:-CHANGELOG.md}
matches "$version" "$VERSION_RE" ||
  die "'$version' is not vX.Y.Z[-pre]"
[ -f "$changelog" ] || die "$changelog not found"

anchor=$(version_anchor "$version")

count=$(grep -Ec "$anchor" "$changelog" || true)
[ "$count" -ne 0 ] || die "$changelog has no section heading for $version"
[ "$count" -eq 1 ] || die "$changelog has $count section headings for $version; refusing to guess which one is the release"

# The anchor reaches awk through the environment: `awk -v` would process its
# backslashes as escape sequences and match a different expression.
body=$(ANCHOR=$anchor awk '
  !inside && $0 ~ ENVIRON["ANCHOR"] { inside = 1; next }
  inside && /^##? / { exit }
  inside { lines[++n] = $0 }
  END {
    first = 1
    while (first <= n && lines[first] ~ /^[ \t]*$/) first++
    last = n
    # Trailing blanks and link reference definitions, in any interleaving.
    while (last >= first && (lines[last] ~ /^[ \t]*$/ || lines[last] ~ /^\[[^]]+\]: /)) last--
    for (i = first; i <= last; i++) print lines[i]
  }
' "$changelog")

[ -n "$body" ] || die "the $version section of $changelog is empty"
printf '%s\n' "$body"

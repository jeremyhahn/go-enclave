#!/bin/sh
# release-notes.sh — print one version's CHANGELOG section, for a release body.
#
# Usage: scripts/release-notes.sh <vX.Y.Z[-pre]> [CHANGELOG.md]
#
# Prints the body of the `## [<version>] - <date>` section — everything after
# the heading up to the next `#`/`##` heading — with leading and trailing blank
# lines removed. The heading anchor is the one scripts/changelog-assemble.sh
# writes and `make release-alpha` checks, bracketed or not, so a version is
# never matched by a longer one that starts with it (v0.6.2 is not v0.6.20,
# v0.6.2-alpha is not v0.6.2-alpha.1).
#
# Link reference definitions at the very end of a section (`[v0.1.0]: https://…`,
# the Keep a Changelog footer) belong to the file, not to the last section, and
# are not printed.
#
# Fails, printing nothing, when the file has no section for the version, has
# more than one (which section would be published is then a guess), or the
# section is empty — a release whose notes say nothing is a release whose
# CHANGELOG step was skipped.
set -eu
export LC_ALL=C

die() { echo "release-notes: $*" >&2; exit 1; }

NL='
'
# matches VALUE ERE: the WHOLE value matches. `grep` alone is line-oriented,
# so a value with an embedded newline would pass on any one matching line.
matches() {
  case $1 in *"$NL"*) return 1 ;; esac
  printf '%s\n' "$1" | grep -Eq "$2"
}

case $# in 1|2) ;; *) die "usage: $0 <vX.Y.Z[-pre]> [CHANGELOG.md]" ;; esac
version=$1
changelog=${2:-CHANGELOG.md}
matches "$version" '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' ||
  die "'$version' is not vX.Y.Z[-pre]"
[ -f "$changelog" ] || die "$changelog not found"

esc=$(printf '%s' "$version" | sed 's/[.]/\\./g')
anchor="^## +\\[?$esc\\]?( |\$)"

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

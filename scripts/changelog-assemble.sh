#!/bin/sh
# changelog-assemble.sh — fold changelog.d/ fragments into CHANGELOG.md.
#
# Usage: scripts/changelog-assemble.sh <vX.Y.Z[-pre]> <YYYY-MM-DD>
#
# Handbook release-versioning §5: a PR adds a fragment
# (changelog.d/<issue>-<slug>.md) instead of editing CHANGELOG.md, and the
# release step concatenates the fragments into the new version's section and
# deletes each one it folds in. Assembly is a COMMITTED step performed before
# tagging, because release.yml never edits or regenerates CHANGELOG.md: it
# reads the COMMITTED file at the tag. It refuses the tag when a fragment or an
# [Unreleased] entry was left out, or the version has no section
# (scripts/release-check-tag.sh), and publishes that section verbatim as the
# release body (scripts/release-notes.sh). So a fragment this script does not
# fold in never reaches a release; it stops the release instead. `make
# release-alpha` runs this script and commits the result with VERSION.
#
# What it does, run from the repository root:
#   - the body of `## [Unreleased]` (entries written before fragments were
#     adopted) and every fragment, in file-name order, are merged under their
#     `### <Subsection>` headings — one heading per distinct subsection, in
#     order of first appearance — into a new `## [<version>] - <date>` section
#     directly below an emptied `## [Unreleased]`;
#   - every folded fragment is deleted; changelog.d/.gitkeep stays.
#
# It fails, changing nothing, when: the version section already exists and
# fragments are still waiting, or `## [Unreleased]` still holds an entry
# (either would be silently left out); there is no
# `## [Unreleased]` heading; a fragment or the Unreleased body has text outside
# a `### ` subsection, or a `#`/`##` heading of its own; or there is nothing at
# all to release. When the version section already exists, no fragment is
# waiting and [Unreleased] is empty it is a no-op, so a section written by
# hand still releases.
set -eu
export LC_ALL=C

die() { echo "changelog-assemble: $*" >&2; exit 1; }

NL='
'
# matches VALUE ERE: the WHOLE value matches. `grep` alone is line-oriented,
# so a value with an embedded newline would pass on any one matching line.
matches() {
  case $1 in *"$NL"*) return 1 ;; esac
  printf '%s\n' "$1" | grep -Eq "$2"
}

[ $# -eq 2 ] || die "usage: $0 <vX.Y.Z[-pre]> <YYYY-MM-DD>"
version=$1
date=$2
matches "$version" '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' || die "'$version' is not vX.Y.Z[-pre]"
matches "$date" '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' || die "'$date' is not YYYY-MM-DD"

changelog=CHANGELOG.md
fragdir=changelog.d
[ -f "$changelog" ] || die "$changelog not found (run from the repository root)"

# Fragments in a stable order. The glob is sorted under LC_ALL=C.
set --
if [ -d "$fragdir" ]; then
  for f in "$fragdir"/*.md; do
    [ -f "$f" ] && set -- "$@" "$f"
  done
fi

# The version heading, bracketed or not — the same anchor the release recipe
# checks for.
esc=$(printf '%s' "$version" | sed 's/[.]/\\./g')
if grep -Eq "^## +\[?$esc\]?( |\$)" "$changelog"; then
  [ $# -eq 0 ] || die "$changelog already has a section for $version but $# fragment(s) are still in $fragdir/ — they would be left out of the release: $*"
  # The same hazard from the other side: entries still under [Unreleased]
  # would be tagged OUTSIDE the release they were written for. A bare
  # `### ` heading is not an entry — the fold drops empty subsections too —
  # but any other non-blank line is, stray text included.
  pending=$(awk '
    /^## +\[Unreleased\][ \t]*$/ { inside = 1; next }
    inside && /^## / { exit }
    inside && /^### / { next }
    inside && !/^[ \t]*$/ { print; exit }
  ' "$changelog")
  [ -z "$pending" ] || die "$changelog already has a section for $version but [Unreleased] still holds entries — they would be left out of the release: $pending"
  echo "changelog-assemble: $changelog already has a section for $version, no fragment is waiting and [Unreleased] is empty; nothing to do"
  exit 0
fi

tmp=$(mktemp "${changelog}.XXXXXX")
trap 'rm -f "$tmp"' EXIT

awk -v version="$version" -v date="$date" -v changelog="$changelog" '
function fail(msg) { print "changelog-assemble: " msg > "/dev/stderr"; failed = 1; exit 1 }
# add appends one line of a block to the current subsection, holding blank
# lines back so a block contributes no leading or trailing blanks.
function add(line) {
  if (line ~ /^[ \t]*$/) { if (started) pending++; return }
  if (!(cur in body)) { order[++n] = cur; body[cur] = "" }
  if (!started && body[cur] != "") body[cur] = body[cur] "\n"   # one blank between blocks
  while (pending > 0) { body[cur] = body[cur] "\n"; pending-- }
  body[cur] = body[cur] line "\n"
  started = 1; entries++
}
function heading(line) { cur = line; started = 0; pending = 0 }
function stray(where, line) {
  if (line ~ /^[ \t]*$/) return 0
  fail(where ": text outside a ### subsection: " line)
}
FILENAME == changelog {
  if (state == 0) {
    pre = pre $0 "\n"
    if ($0 ~ /^## +\[Unreleased\][ \t]*$/) { state = 1; cur = "" }
    next
  }
  if (state == 1) {
    if ($0 ~ /^## /) { state = 2; rest = $0 "\n"; next }
    if ($0 ~ /^# /) fail(changelog ": a # heading inside [Unreleased]: " $0)
    if ($0 ~ /^### /) { heading($0); next }
    if (cur == "") { stray(changelog " [Unreleased]", $0); next }
    add($0); next
  }
  rest = rest $0 "\n"; next
}
FNR == 1 { cur = ""; started = 0; pending = 0 }
{
  if ($0 ~ /^##? / || $0 ~ /^#[ \t]*$/) fail(FILENAME ": a fragment holds ### subsections only, not: " $0)
  if ($0 ~ /^### /) { heading($0); next }
  if (cur == "") { stray(FILENAME, $0); next }
  add($0)
}
END {
  if (failed) exit 1
  if (state == 0) { print "changelog-assemble: " changelog " has no ## [Unreleased] heading" > "/dev/stderr"; exit 1 }
  if (entries == 0) { print "changelog-assemble: nothing to release: [Unreleased] is empty and no fragment is waiting" > "/dev/stderr"; exit 1 }
  printf "%s\n## [%s] - %s\n", pre, version, date
  for (i = 1; i <= n; i++) printf "\n%s\n\n%s", order[i], body[order[i]]
  if (rest != "") printf "\n%s", rest
}
' "$changelog" "$@" > "$tmp"

cat "$tmp" > "$changelog"   # keeps the file's mode; mktemp creates 0600
rm -f "$tmp"
trap - EXIT
[ $# -eq 0 ] || rm -f "$@"
echo "changelog-assemble: folded $# fragment(s) into $changelog under [$version] - $date"

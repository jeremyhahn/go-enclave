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
# release` runs this script and commits the result with VERSION.
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
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 2 ] || die "usage: $0 <vX.Y.Z[-pre]> <YYYY-MM-DD>"
version=$1
date=$2
matches "$version" "$VERSION_RE" || die "'$version' is not vX.Y.Z[-pre]"
matches "$date" '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' || die "'$date' is not YYYY-MM-DD"

changelog=CHANGELOG.md
fragdir=changelog.d
[ -f "$changelog" ] || die "$changelog not found (run from the repository root)"

# Fragments in a stable order: numerically by issue (the leading digits of the
# file name, so 9x folds before 10x), then by file name under LC_ALL=C.
set --
if [ -d "$fragdir" ]; then
  tab=$(printf '\t')
  keyed=
  for f in "$fragdir"/*.md; do
    [ -f "$f" ] || continue
    b=${f##*/}
    keyed=$keyed$(printf '%s\t%s' "$(printf '%s' "${b%%[!0-9]*}" | sed 's/^0*//;s/^$/0/')" "$f")$NL
  done
  if [ -n "$keyed" ]; then
    sorted=$(printf '%s' "$keyed" | LC_ALL=C sort -t "$tab" -k1,1n -k2,2)
    old_ifs=$IFS; IFS=$NL
    for line in $sorted; do
      set -- "$@" "${line#*"$tab"}"
    done
    IFS=$old_ifs
  fi
fi

if grep -Eq "$(version_anchor "$version")" "$changelog"; then
  [ $# -eq 0 ] || die "$changelog already has a section for $version but $# fragment(s) are still in $fragdir/ — they would be left out of the release: $*"
  # The same hazard from the other side: entries still under [Unreleased]
  # would be tagged OUTSIDE the release they were written for.
  pending=$(unreleased_pending "$changelog")
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

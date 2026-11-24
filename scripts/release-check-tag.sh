#!/bin/sh
# release-check-tag.sh <tag>: refuse a release tag that disagrees with VERSION, CHANGELOG.md or changelog.d/, reporting every failure.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 1 ] || { echo "usage: $0 <tag>" >&2; exit 2; }
tag=$1

bad=0
fail() { echo "$prog: $*" >&2; bad=1; }

if ! matches "$tag" "$RELEASE_TAG_RE"; then
  fail "tag '$tag' is not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N (release-versioning §1, §1a)"
fi

if [ ! -f VERSION ]; then
  fail "VERSION not found (run from the repository root)"
else
  # Compared byte for byte, apart from the one trailing newline `echo` writes:
  # a stray space, a second line or a `v` prefix is a defect, not something to
  # normalise away.
  lines=$(wc -l < VERSION | tr -d ' ')
  version=$(cat VERSION)
  if [ "$lines" -gt 1 ]; then
    fail "VERSION holds $lines lines; it must hold the one unprefixed version"
  elif [ "v$version" != "$tag" ]; then
    fail "VERSION reads '$version' but the tag is '$tag'; the file must read '${tag#v}' (unprefixed, release-versioning §2)"
  fi
fi

if [ ! -f CHANGELOG.md ]; then
  fail "CHANGELOG.md not found"
else
  sh "$here/release-notes.sh" "$tag" CHANGELOG.md >/dev/null || fail "CHANGELOG.md has no usable section for $tag (see above)"

  pending=$(unreleased_pending CHANGELOG.md)
  [ -z "$pending" ] || fail "[Unreleased] still holds entries the $tag release leaves out: $pending"
fi

if [ -d changelog.d ]; then
  for f in changelog.d/*.md; do
    [ -e "$f" ] && fail "fragment $f was never folded into the $tag section (the release targets assemble before tagging)"
  done
fi

[ "$bad" -eq 0 ] || exit 1
echo "$prog: $tag agrees with VERSION and CHANGELOG.md"

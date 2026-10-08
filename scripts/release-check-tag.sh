#!/bin/sh
# release-check-tag.sh — refuse a release tag that disagrees with its own tree.
#
# Usage: scripts/release-check-tag.sh <tag>      (run from the repository root)
#
# release.yml runs this first (through `make release-verify`), on the tagged
# commit, before any gate or publication; the release targets
# (`make release`, `make release-candidate`, `make release-alpha`) run it before
# they commit. The tag and the tree carry the version in three places that
# nothing else reconciles (release-versioning §2, its PROPOSED P4: "a CI
# check failing when v$(cat VERSION) != the tag … plus a check for a matching
# CHANGELOG entry — the third thing that drifts"):
#
#   - the tag is vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N (N from 1, no leading
#     zeros) — the only pre-releases in use (release-versioning §1, §1a);
#     anything else is a typo or an unsanctioned kind;
#   - VERSION holds exactly the tag without its `v` (§2: the file is
#     unprefixed, the tag prefixed);
#   - CHANGELOG.md has exactly one non-empty section for the tag
#     (scripts/release-notes.sh, which also produces the release body);
#   - no fragment is left in changelog.d/ and `## [Unreleased]` holds no
#     entry: the release targets fold both into the version's section before
#     tagging (§5), so either one surviving at a tag is an entry the release
#     leaves out.
#
# Every failure is reported, not just the first, so one run says everything
# that has to change.
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

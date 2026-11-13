#!/bin/sh
# release-tree-check.sh — the published commit's tree is the tag's tree.
#
# Usage: scripts/release-tree-check.sh <tag> <published-ref>   (from the repository root)
#
# The body of `make release-tree-check TAG=… REF=…` (SPEC release criterion 8:
# the release is published as one commit whose tree is byte-identical to the
# tag's tree). Offline: it resolves <tag>^{commit} and <ref>^{commit} in the
# local clone, compares the two commits' trees, and refuses when they differ or
# either does not name a commit (a bare tree is refused), or when the
# tag is not a release version. It writes nothing and makes no network call.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 2 ] || die "usage: $0 <tag> <published-ref> (TAG and REF are both required)"
tag=$1
ref=$2
[ -n "$tag" ] || die "TAG=vX.Y.Z[-pre] is required"
[ -n "$ref" ] || die "REF=<published ref> is required"
matches "$tag" "$RELEASE_TAG_RE" ||
  die "tag '$tag' is not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N (release-versioning §1, §1a)"
case $ref in
  -*|*[!A-Za-z0-9._/-]*) die "REF is not a plain ref name; refusing it" ;;
esac

# Both must name commits: a tree object (or a tag pointing at one) has a tree
# but is not the one published commit criterion 8 asks for.
tag_commit=$(git rev-parse --verify --quiet --end-of-options "refs/tags/$tag^{commit}") ||
  die "TAG '$tag' does not name a commit in this clone"
ref_commit=$(git rev-parse --verify --quiet --end-of-options "$ref^{commit}") ||
  die "REF '$ref' does not name a commit in this clone"
tag_tree=$(git rev-parse --verify --quiet "$tag_commit^{tree}") ||
  die "cannot read the tree of $tag ($tag_commit)"
ref_tree=$(git rev-parse --verify --quiet "$ref_commit^{tree}") ||
  die "cannot read the tree of $ref ($ref_commit)"

[ "$tag_tree" = "$ref_tree" ] ||
  die "the tree of $ref ($ref_tree) is not the tree of $tag ($tag_tree)"
echo "$prog: $ref has the tree of $tag ($tag_tree)"

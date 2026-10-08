#!/bin/sh
# release-verify.sh — the tag agrees with VERSION and CHANGELOG.md (and is on MAIN_REF).
#
# Usage: scripts/release-verify.sh <tag> [<main-ref>]   (from the repository root)
#
# The body of `make release-verify TAG=… [MAIN_REF=…]`. See release-check-tag.sh.
# With a main ref, HEAD must be an ancestor of it.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -ge 1 ] || die "usage: $0 <tag> [<main-ref>]"
tag=$1
ref=${2-}
[ -n "$tag" ] || die "TAG=vX.Y.Z[-pre] is required"
if [ -n "$ref" ]; then
  case $ref in
    -*|*[!A-Za-z0-9._/-]*) die "MAIN_REF is not a plain ref name; refusing it" ;;
  esac
fi

sh "$here/release-check-tag.sh" "$tag"

if [ -n "$ref" ]; then
  main=$(git rev-parse --verify --quiet --end-of-options "$ref^{commit}") || die "MAIN_REF '$ref' does not name a commit"
  git merge-base --is-ancestor HEAD "$main" || die "HEAD $(git rev-parse HEAD) is not on $ref"
  echo "$prog: HEAD is on $ref"
fi

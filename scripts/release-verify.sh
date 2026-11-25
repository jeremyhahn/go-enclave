#!/bin/sh
# release-verify.sh <tag> [<main-ref>]: release-check-tag.sh, plus HEAD must be an ancestor of main-ref.
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

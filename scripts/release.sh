#!/bin/sh
# release.sh — cut a signed release of one kind:
#   make release-alpha     VERSION=vX.Y.Z-alpha
#   make release-candidate VERSION=vX.Y.Z-rc.N
#   make release           VERSION=vX.Y.Z
#
# Usage: scripts/release.sh <alpha|candidate|release>   (from the repository root)
#
# The argument is the kind the Makefile target stands for; the version must be
# of exactly that kind and the other two are refused (release-versioning §1,
# §1a). All three targets run this one script.
#
# Environment (exported by the Makefile, read raw): VERSION, AGENT_GIT (the
# commit/signing wrapper, no default: this fails closed without it) and
# REPO_NAME (the literal repo name, which selects the signing identity).
#
# The version is explicit, never derived. Before anything is written: VERSION
# must have the form of its kind, be cut from main, move forward
# (release-version-check.sh), the tag must be free locally and on dev (ls-remote
# exit 2 is the only "free"; anything else fails closed), the tree must be
# clean, and the assembled tree must pass release-check-tag.sh (no fragment
# left, a literal `## [vX.Y.Z…]` heading). VERSION is written unprefixed, by
# overwriting, so repeating the step leaves the same bytes; changelog.d/
# fragments fold into CHANGELOG.md in the same commit. Pushing the tag hands
# off to release.yml.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 1 ] || die "usage: $0 <alpha|candidate|release>"
kind=$1
case $kind in
  alpha)     target="make release-alpha VERSION=vX.Y.Z-alpha";     forms="vX.Y.Z-alpha";  suffix='^v[^-]+-alpha$' ;;
  candidate) target="make release-candidate VERSION=vX.Y.Z-rc.N";  forms="vX.Y.Z-rc.N";   suffix='^v[^-]+-rc\.[0-9]+$' ;;
  release)   target="make release VERSION=vX.Y.Z";                 forms="vX.Y.Z";        suffix='' ;;
  *) die "usage: $0 <alpha|candidate|release>" ;;
esac

version=${VERSION-}
agent_git=${AGENT_GIT-}
repo_name=${REPO_NAME-}

case $version in
  '') die "state the version explicitly: $target (release-versioning.md decides patch/minor/major — the recipe refuses to guess)" ;;
  *[!0-9A-Za-z.-]*) die "VERSION holds characters no release version does; refusing it" ;;
esac
matches "$version" "$RELEASE_TAG_RE" || die "'$version' is not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N"
if [ -n "$suffix" ]; then
  matches "$version" "$suffix" || die "'$version' is not $forms; $target cuts only that kind"
else
  case $version in
    *-*) die "'$version' is not $forms; make release cuts only production versions (use make release-alpha or make release-candidate)" ;;
  esac
fi
[ -n "$agent_git" ] || die "AGENT_GIT is unset - point it at your commit-signing/release wrapper (maintainer tooling; not needed to build or test)"
branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = main ] || die "releases are cut from main; you are on $branch. 'push dev HEAD' would publish this branch to dev."
[ -n "$repo_name" ] || die "REPO_NAME is empty — set it to the literal repo name in the Makefile, never \$(notdir \$(CURDIR))"
! git rev-parse -q --verify "refs/tags/$version" >/dev/null || die "tag $version already exists locally"
git remote get-url dev >/dev/null 2>&1 || die "no 'dev' remote. The Gitea remote is named dev (version-control.md §2): git remote rename origin dev"
rc=0
git ls-remote --exit-code --tags dev "refs/tags/$version" >/dev/null 2>&1 || rc=$?
case $rc in
  0) die "tag $version already exists on dev (a local check alone would miss this and fail the push AFTER committing VERSION)" ;;
  2) ;;
  *) die "could not query dev for tag $version (git ls-remote exit $rc) — refusing to release on an unanswered check" ;;
esac
[ -z "$(git status --porcelain)" ] || die "working tree not clean"

sh "$here/release-version-check.sh" "$version"
sh "$here/changelog-assemble.sh" "$version" "$(date -u +%Y-%m-%d)"
printf '%s\n' "${version#v}" > VERSION
sh "$here/release-check-tag.sh" "$version" || die "the assembled tree would be refused by release.yml; nothing was committed (git checkout -- VERSION CHANGELOG.md changelog.d to start over)"

"$agent_git" "$repo_name" add -A -- VERSION CHANGELOG.md changelog.d
"$agent_git" "$repo_name" commit -m "chore(release): $version"
"$agent_git" "$repo_name" tag -a "$version" -m "$version"
"$agent_git" "$repo_name" push dev HEAD "refs/tags/$version"
echo "Released $version (signed, annotated, single tag pushed); release.yml gates it and publishes the Gitea release"

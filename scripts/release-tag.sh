#!/bin/sh
# release-tag.sh — the second of a release's two steps: tag the merged release
# commit.
#   make release-tag VERSION=vX.Y.Z[-alpha|-rc.N]
#
# Usage: scripts/release-tag.sh   (from the repository root)
#
# Run after the pull request release.sh's branch release/<version> was opened
# for has merged into main. Environment as for release.sh: VERSION, AGENT_GIT,
# REPO_NAME, and FORGE_API_URL, FORGE_REPOSITORY and FORGE_TOKEN (a read token).
#
# Before it tags, it refuses unless: VERSION is a release version; the local
# checkout is a clean main that is dev's main as just fetched; that HEAD is the
# merged release commit, i.e. VERSION there is the version and its parent's is
# not; the version is strictly greater than that parent's VERSION and every
# existing v* tag, dev's fetched first (release-version-check.sh, as release.sh runs it: an older
# release pull request merged after a newer release must not be tagged);
# and the tree passes release-check-tag.sh (no fragment left, a literal
# `## [vX.Y.Z…]` heading); the tag is free locally and on dev; the forge names
# HEAD as the merge commit of a merged pull request from release/<version>
# into main; and that pull request's head has a CI Gate check run of success.
#
# The CI Gate read is the release pull request's head, not main's HEAD: when
# the release ships the fix for a red main job, main's own run of the merge
# commit can still be red for exactly the reason the release fixes, and the
# ruleset admitted the merge on the pull request's CI Gate. See
# release-ci-gate.sh.
#
# Then it creates the signed annotated tag on HEAD, reads dev's tags again and
# refuses (deleting the local tag) when they changed since the precedence
# check, and otherwise pushes the tag alone; main is not pushed. Pushing the
# tag hands off to release.yml, which gates the tagged commit again (that it
# is on main, and that the tag is greater than every other v* tag on the
# forge, in serialized runs) before anything is published.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 0 ] || die "usage: VERSION=vX.Y.Z[-alpha|-rc.N] $0"
version=${VERSION-}
agent_git=${AGENT_GIT-}
repo_name=${REPO_NAME-}

case $version in
  '') die "state the version explicitly: make release-tag VERSION=vX.Y.Z[-alpha|-rc.N], the version the merged release pull request set" ;;
  *[!0-9A-Za-z.-]*) die "VERSION holds characters no release version does; refusing it" ;;
esac
matches "$version" "$RELEASE_TAG_RE" || die "'$version' is not vX.Y.Z, vX.Y.Z-alpha or vX.Y.Z-rc.N"
[ -n "$agent_git" ] || die "AGENT_GIT is unset - point it at your commit-signing/release wrapper (maintainer tooling; not needed to build or test)"
[ -n "$repo_name" ] || die "REPO_NAME is empty — set it to the literal repo name in the Makefile, never \$(notdir \$(CURDIR))"
branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = main ] || die "releases are tagged from main; you are on $branch"
! git rev-parse -q --verify "refs/tags/$version" >/dev/null || die "tag $version already exists locally"
git remote get-url dev >/dev/null 2>&1 || die "no 'dev' remote. The GitHub remote is named dev: git remote rename origin dev"
rc=0
"$agent_git" "$repo_name" ls-remote --exit-code --tags dev "refs/tags/$version" >/dev/null 2>&1 || rc=$?
case $rc in
  0) die "tag $version already exists on dev" ;;
  2) ;;
  *) die "could not query dev for tag $version (git ls-remote exit $rc) — refusing to tag on an unanswered check" ;;
esac
[ -z "$(git status --porcelain)" ] || die "working tree not clean"

"$agent_git" "$repo_name" fetch --quiet dev main || die "could not fetch main from dev; refusing to tag on an unanswered check"
remote_main=$(git rev-parse -q --verify 'FETCH_HEAD^{commit}') || die "dev has no main to compare against"
head_sha=$(git rev-parse HEAD)
[ "$head_sha" = "$remote_main" ] || die "local main ($head_sha) is not dev/main ($remote_main); update it first (git pull --ff-only dev main)"

want=${version#v}
have=$(cat VERSION 2>/dev/null) || have=
[ "$have" = "$want" ] || die "VERSION on main is ${have:-missing}, not $want; tag only the merged release commit of $version"
parent=$(git show HEAD^:VERSION 2>/dev/null) || parent=
[ "$parent" != "$want" ] || die "main's HEAD $head_sha is not the commit that set VERSION to $want (its parent already has it); tag the release pull request's merge commit, before anything merged after it"
# Order against every release tag on dev, not only the ones this clone has:
# no '+' on the refspec, so a local tag that differs from dev's fails the
# fetch instead of being overwritten. dev's tag list is read before the fetch
# and again just before the push: a tag another maintainer pushed in between
# (while this script waited on the forge, say) was never ordered against, so
# the tag is not pushed.
dev_tags() { "$agent_git" "$repo_name" ls-remote --tags dev; }
ordered_tags=$(dev_tags) || die "could not list dev's tags; refusing to order $version against an unanswered list"
"$agent_git" "$repo_name" fetch --quiet --no-tags dev 'refs/tags/v*:refs/tags/v*' || die "could not fetch dev's release tags (or a local tag differs from dev's); refusing to order $version against a partial list"
[ -n "$parent" ] || die "main's HEAD $head_sha has a first parent with no VERSION to order $version against"
sh "$here/release-version-check.sh" "$version" "$parent" || die "$version does not move forward from the first parent's VERSION ($parent) and every release tag; a release pull request prepared before a newer release must be prepared again at a higher version"
sh "$here/release-check-tag.sh" "$version" || die "main's tree would be refused by release.yml for $version"

sh "$here/release-ci-gate.sh" merged "$head_sha" "release/$version" >/dev/null

"$agent_git" "$repo_name" tag -a "$version" -m "$version" "$head_sha"
# The window between this read and the push is closed by release.yml, which
# orders the pushed tag against every other tag on the forge again, in runs
# its concurrency group serializes, before it publishes anything.
untag() { git tag -d "$version" >/dev/null 2>&1 || true; }
pushed_tags=$(dev_tags) || { untag; die "could not list dev's tags again before the push; refusing to push $version on an unanswered check"; }
[ "$pushed_tags" = "$ordered_tags" ] || { untag; die "dev's tags changed since $version was ordered against them (another release was tagged meanwhile); nothing pushed. Run make release-tag again: it orders $version against the new tags"; }
"$agent_git" "$repo_name" push dev "refs/tags/$version" || { untag; die "could not push tag $version to dev"; }
echo "Tagged $version on $head_sha (signed, annotated) and pushed the tag alone; release.yml gates it and publishes the release"

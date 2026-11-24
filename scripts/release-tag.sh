#!/bin/sh
# release-tag.sh: tag the merged release commit after every release check passes, pushing the tag with the release lock atomically (make release-tag VERSION=...).
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
# The release lock is one ref on dev, read before the precedence check and moved with the tag in a leased push.
lock_ref=refs/heads/release-lock
lock_line=$("$agent_git" "$repo_name" ls-remote dev "$lock_ref") || die "could not read dev's $lock_ref; refusing to order $version against an unanswered read"
lock=$(printf '%s\n' "$lock_line" | awk -v r="$lock_ref" '$2 == r { print $1 }')
[ -z "$lock" ] || matches "$lock" '^([0-9a-f]{40}|[0-9a-f]{64})$' || die "dev's $lock_ref reads '$lock', not an object name; refusing to lease on it"
# Order against every release tag on dev, not only the ones this clone has:
# no '+' on the refspec, so a local tag that differs from dev's fails the
# fetch instead of being overwritten.
"$agent_git" "$repo_name" fetch --quiet --no-tags dev 'refs/tags/v*:refs/tags/v*' || die "could not fetch dev's release tags (or a local tag differs from dev's); refusing to order $version against a partial list"
[ -n "$parent" ] || die "main's HEAD $head_sha has a first parent with no VERSION to order $version against"
sh "$here/release-version-check.sh" "$version" "$parent" || die "$version does not move forward from the first parent's VERSION ($parent) and every release tag; a release pull request prepared before a newer release must be prepared again at a higher version"
sh "$here/release-check-tag.sh" "$version" || die "main's tree would be refused by release.yml for $version"

sh "$here/release-ci-gate.sh" merged "$head_sha" "release/$version" >/dev/null

"$agent_git" "$repo_name" tag -a "$version" -m "$version" "$head_sha"
untag() { git tag -d "$version" >/dev/null 2>&1 || true; }
"$agent_git" "$repo_name" push --atomic --force-with-lease="$lock_ref:$lock" dev "refs/tags/$version" "$head_sha:$lock_ref" || {
  untag
  die "dev refused tag $version and the move of $lock_ref; nothing was written. If another release was tagged since $version was ordered (the lock moved), run make release-tag again: it orders $version against the new tags"
}
echo "Tagged $version on $head_sha (signed, annotated) and pushed it with dev's $lock_ref, atomically; release.yml gates it"

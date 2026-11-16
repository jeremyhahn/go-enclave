#!/bin/sh
# release.sh — the first of a release's two steps: prepare a signed release
# commit of one kind on release/<version>.
#   make release-alpha     VERSION=vX.Y.Z-alpha
#   make release-candidate VERSION=vX.Y.Z-rc.N
#   make release           VERSION=vX.Y.Z
# The second step, after the release pull request is merged, is
# `make release-tag VERSION=…` (release-tag.sh).
#
# Usage: scripts/release.sh <alpha|candidate|release>   (from the repository root)
#
# The argument is the kind the Makefile target stands for; the version must be
# of exactly that kind and the other two are refused (release-versioning §1,
# §1a). All three targets run this one script.
#
# Environment (exported by the Makefile, read raw): VERSION, AGENT_GIT (the
# commit/signing wrapper, no default: this fails closed without it) and
# REPO_NAME (the literal repo name, which selects the signing identity), and
# FORGE_API_URL, FORGE_REPOSITORY and FORGE_TOKEN (a read token) for the forge's
# CI Gate check run (release-ci-gate.sh).
#
# Every git operation that talks to dev (the tag-free and branch-free
# ls-remote, the fetch of main and the push) runs through "$AGENT_GIT"
# "$REPO_NAME", which carries the agent's credentials and URL rewrite; plain
# git on a maintainer host has no key for dev. Local-only git (rev-parse,
# status, remote get-url, checkout) stays plain.
#
# The version is explicit, never derived. Before anything is written: VERSION
# must have the form of its kind, be cut from main, move forward
# (release-version-check.sh), the tag and the branch release/<version> must be
# free locally and on dev (ls-remote exit 2 is the only "free"; anything else
# fails closed), the tree must be clean, HEAD must be dev's main (fetched, not
# remembered) with a CI Gate check run of success on the forge (an unreachable
# forge refuses), and the assembled tree must pass release-check-tag.sh (no
# fragment left, a literal `## [vX.Y.Z…]` heading). VERSION is written
# unprefixed, by overwriting, so repeating the step leaves the same bytes;
# changelog.d/ fragments fold into CHANGELOG.md in the same commit.
#
# main's ruleset takes a commit only through a pull request whose CI Gate
# passed, so this step pushes release/<version> and nothing else: never main,
# never a tag. The local checkout returns to main. A maintainer opens the pull
# request from the branch it prints; release-tag.sh tags the merge.
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
[ -n "$repo_name" ] || die "REPO_NAME is empty — set it to the literal repo name in the Makefile, never \$(notdir \$(CURDIR))"
branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = main ] || die "releases are cut from main; you are on $branch. 'push dev HEAD' would publish this branch to dev."
! git rev-parse -q --verify "refs/tags/$version" >/dev/null || die "tag $version already exists locally"
git remote get-url dev >/dev/null 2>&1 || die "no 'dev' remote. The Gitea remote is named dev (version-control.md §2): git remote rename origin dev"
rc=0
"$agent_git" "$repo_name" ls-remote --exit-code --tags dev "refs/tags/$version" >/dev/null 2>&1 || rc=$?
case $rc in
  0) die "tag $version already exists on dev (a local check alone would miss this and fail the push AFTER committing VERSION)" ;;
  2) ;;
  *) die "could not query dev for tag $version (git ls-remote exit $rc) — refusing to release on an unanswered check" ;;
esac
release_branch="release/$version"
! git rev-parse -q --verify "refs/heads/$release_branch" >/dev/null || die "branch $release_branch already exists locally (git branch -D $release_branch if it is a failed earlier attempt)"
rc=0
"$agent_git" "$repo_name" ls-remote --exit-code --heads dev "refs/heads/$release_branch" >/dev/null 2>&1 || rc=$?
case $rc in
  0) die "branch $release_branch already exists on dev; a release pull request for $version is already open or was left behind" ;;
  2) ;;
  *) die "could not query dev for branch $release_branch (git ls-remote exit $rc) — refusing to release on an unanswered check" ;;
esac
[ -z "$(git status --porcelain)" ] || die "working tree not clean"

# The commit being released is the tip of dev's main, and CI Gate passed on it
# (release-versioning §1a). A stale local main would put a release commit on a
# base the pull request does not merge cleanly onto; and an unreached forge is
# an error here, never a pass.
"$agent_git" "$repo_name" fetch --quiet dev main || die "could not fetch main from dev; refusing to release on an unanswered check"
remote_main=$(git rev-parse -q --verify 'FETCH_HEAD^{commit}') || die "dev has no main to compare against"
head_sha=$(git rev-parse HEAD)
[ "$head_sha" = "$remote_main" ] || die "local main ($head_sha) is not dev/main ($remote_main); update it first (git pull --ff-only dev main)."
sh "$here/release-ci-gate.sh" commit "$head_sha"

sh "$here/release-version-check.sh" "$version"
sh "$here/changelog-assemble.sh" "$version" "$(date -u +%Y-%m-%d)"
printf '%s\n' "${version#v}" > VERSION
sh "$here/release-check-tag.sh" "$version" || die "the assembled tree would be refused by release.yml; nothing was committed (git checkout -- VERSION CHANGELOG.md changelog.d to start over)"
# The assembled tree carries over onto the new branch; main stays as fetched.
git checkout -q -b "$release_branch"

"$agent_git" "$repo_name" add -A -- VERSION CHANGELOG.md changelog.d
"$agent_git" "$repo_name" commit -m "chore(release): $version"
"$agent_git" "$repo_name" push dev "refs/heads/$release_branch:refs/heads/$release_branch"
git checkout -q main
echo "Prepared $version on $release_branch (signed, pushed; main and the tag untouched)."
echo "Next: open a pull request from $release_branch into main; when it has merged, run make release-tag VERSION=$version"

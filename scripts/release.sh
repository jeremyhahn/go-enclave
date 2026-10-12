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
# REPO_NAME (the literal repo name, which selects the signing identity), and
# FORGE_API_URL, FORGE_REPOSITORY and FORGE_TOKEN (a read token) for the forge's
# combined commit status.
#
# Every git operation that talks to dev (the tag-free ls-remote, the fetch of
# main and the push) runs through "$AGENT_GIT" "$REPO_NAME", which carries the
# agent's credentials and URL rewrite; plain git on a maintainer host has no key
# for dev. Local-only git (rev-parse, status, remote get-url) stays plain.
#
# The version is explicit, never derived. Before anything is written: VERSION
# must have the form of its kind, be cut from main, move forward
# (release-version-check.sh), the tag must be free locally and on dev (ls-remote
# exit 2 is the only "free"; anything else fails closed), the tree must be
# clean, HEAD must be dev's main (fetched, not remembered) with a green combined
# status on the forge (an unreachable forge refuses), and the assembled tree
# must pass release-check-tag.sh (no fragment
# left, a literal `## [vX.Y.Z…]` heading). VERSION is written unprefixed, by
# overwriting, so repeating the step leaves the same bytes; changelog.d/
# fragments fold into CHANGELOG.md in the same commit. main and the tag go in
# one atomic push, so a rejected main never leaves the tag behind. Pushing the
# tag hands off to release.yml.
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
[ -z "$(git status --porcelain)" ] || die "working tree not clean"

# The commit being released is the tip of dev's main, and the forge says CI is
# green on it (release-versioning §1a). A stale local main would have its main
# push rejected while the tag still landed, burning an immutable tag; and an
# unreached forge is an error here, never a pass.
"$agent_git" "$repo_name" fetch --quiet dev main || die "could not fetch main from dev; refusing to release on an unanswered check"
remote_main=$(git rev-parse -q --verify 'FETCH_HEAD^{commit}') || die "dev has no main to compare against"
head_sha=$(git rev-parse HEAD)
[ "$head_sha" = "$remote_main" ] || die "local main ($head_sha) is not dev/main ($remote_main); update it first (git pull --ff-only dev main). Releasing from it would push a tag the main push does not accompany."

api=${FORGE_API_URL-}
forge_repo=${FORGE_REPOSITORY-}
token=${FORGE_TOKEN-}
[ -n "$api" ] || die "FORGE_API_URL is unset - the release needs the forge's combined commit status for main (e.g. https://git.example.com/api/v1)"
[ -n "$forge_repo" ] || die "FORGE_REPOSITORY is unset - set it to owner/repo"
[ -n "$token" ] || die "FORGE_TOKEN is unset - the release needs a read token for the forge's commit status"
# The token is written into a curl configuration line, so anything but a forge
# token's own characters is refused, not escaped (release-publish.sh, same rule).
case $token in
  *[!A-Za-z0-9_.-]*) die "FORGE_TOKEN has characters no forge token carries; refusing to use it" ;;
esac
case $api in
  *[!A-Za-z0-9._~:/?#@!\$\&\'\(\)*+,\;=%-]*) die "FORGE_API_URL contains characters a URL does not" ;;
  http://*|https://*) ;;
  *) die "FORGE_API_URL '$api' is not an http(s) URL" ;;
esac
api=${api%/}
matches "$forge_repo" '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || die "FORGE_REPOSITORY '$forge_repo' is not owner/repo"
for t in curl jq; do
  command -v "$t" >/dev/null 2>&1 || die "$t is required to read the forge's commit status and was not found"
done
work=$(mktemp -d "${TMPDIR:-/tmp}/release.XXXXXX")
trap 'rm -rf "$work"' EXIT
code=$(printf 'header = "Authorization: token %s"\n' "$token" |
  curl --silent --show-error --config - --connect-timeout 10 --max-time 60 \
    -H 'Accept: application/json' -o "$work/status" -w '%{http_code}' \
    "$api/repos/$forge_repo/commits/$head_sha/status") || code=000
[ "$code" = 200 ] || die "could not read the forge's commit status for $head_sha (HTTP $code); refusing to release on an unanswered check"
state=$(jq -r --arg sha "$head_sha" 'select(.sha == $sha) | .state // empty' "$work/status" 2>/dev/null) || state=
[ "$state" = success ] || die "CI is not green on $head_sha (combined status '${state:-unreadable}'); a release is cut only from a commit whose checks all passed"

sh "$here/release-version-check.sh" "$version"
sh "$here/changelog-assemble.sh" "$version" "$(date -u +%Y-%m-%d)"
printf '%s\n' "${version#v}" > VERSION
sh "$here/release-check-tag.sh" "$version" || die "the assembled tree would be refused by release.yml; nothing was committed (git checkout -- VERSION CHANGELOG.md changelog.d to start over)"

"$agent_git" "$repo_name" add -A -- VERSION CHANGELOG.md changelog.d
"$agent_git" "$repo_name" commit -m "chore(release): $version"
"$agent_git" "$repo_name" tag -a "$version" -m "$version"
"$agent_git" "$repo_name" push --atomic dev HEAD:main "refs/tags/$version"
echo "Released $version (signed, annotated, main and the tag pushed atomically); release.yml gates it and publishes the Gitea release"

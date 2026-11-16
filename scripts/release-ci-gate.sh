#!/bin/sh
# release-ci-gate.sh — read the forge's CI Gate check run on the release pull
# request before release-tag.sh tags.
#
# Usage (from the repository root; release-tag.sh runs it):
#   scripts/release-ci-gate.sh merged <sha> <branch>
#       <sha> must be the merge commit of a merged pull request from <branch>
#       into main, and CI Gate on that pull request's head must be success.
#       Prints the pull request's number and head.
#
# Environment: FORGE_API_URL (the API root, https://api.github.com),
# FORGE_REPOSITORY (owner/repo) and FORGE_TOKEN (a read token). GitHub is the
# repository's only forge (dev is its remote), so GitHub's REST API is the
# only one read here.
#
# CI Gate is the one check the main ruleset requires, and GitHub reports it
# as a check run, not a commit status: the legacy combined status of a commit
# whose CI is all check runs reads `pending` with no statuses for ever. So the
# read is GET /repos/<owner>/<repo>/commits/<sha>/check-runs?check_name=CI%20Gate,
# and the latest run (the highest id) must be completed with conclusion
# success. Anything else (no run, a run in progress, any other conclusion, an
# HTTP error, an answer that does not parse) refuses: an unanswered check is
# never a pass.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

usage="usage: $0 merged <sha> <release-branch>"
[ $# -eq 3 ] && [ "$1" = merged ] || die "$usage"
sha=$2
branch=$3
matches "$sha" '^[0-9a-f]{40}$' || die "'$sha' is not a full commit id"
matches "$branch" '^release/v[0-9A-Za-z.-]+$' || die "'$branch' is not a release branch"

api=${FORGE_API_URL-}
forge_repo=${FORGE_REPOSITORY-}
token=${FORGE_TOKEN-}
[ -n "$api" ] || die "FORGE_API_URL is unset - the release reads the forge's CI Gate check run (e.g. https://api.github.com)"
[ -n "$forge_repo" ] || die "FORGE_REPOSITORY is unset - set it to owner/repo"
[ -n "$token" ] || die "FORGE_TOKEN is unset - the release needs a read token for the forge's check runs"
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
  command -v "$t" >/dev/null 2>&1 || die "$t is required to read the forge's check runs and was not found"
done
work=$(mktemp -d "${TMPDIR:-/tmp}/release-ci-gate.XXXXXX")
trap 'rm -rf "$work"' EXIT

# get <path> <out>: GET $api/repos/$forge_repo/<path> into <out>; prints the
# HTTP code, 000 when the forge was not reached.
get() {
  printf 'header = "Authorization: token %s"\n' "$token" |
    curl --silent --show-error --config - --connect-timeout 10 --max-time 60 \
      -H 'Accept: application/vnd.github+json' -o "$2" -w '%{http_code}' \
      "$api/repos/$forge_repo/$1"
}

# ci_gate <sha> <what>: CI Gate on <sha> is success, or refuse naming <what>.
ci_gate() {
  code=$(get "commits/$1/check-runs?check_name=CI%20Gate" "$work/runs") || code=000
  [ "$code" = 200 ] || die "could not read the forge's CI Gate check run for $2 $1 (HTTP $code); refusing to release on an unanswered check"
  state=$(jq -r --arg sha "$1" '
    [.check_runs[]? | select(.name == "CI Gate" and .head_sha == $sha)]
    | if length == 0 then "missing"
      else max_by(.id) | if .status != "completed" then "pending" else (.conclusion // "none") end
      end' "$work/runs" 2>/dev/null) || state=
  [ "$state" = success ] || die "CI Gate is not success on $2 $1 (check run '${state:-unreadable}'); a release is tagged only when its pull request's CI Gate passed"
}

# main's own CI Gate run is not the one read here: when a release ships the
# fix for a red main job, main's run of the merge commit can still be red for
# exactly the reason the release fixes. The ruleset let the merge in on the
# pull request's CI Gate, so that run is the one required.
code=$(get "commits/$sha/pulls" "$work/pulls") || code=000
[ "$code" = 200 ] || die "could not read the forge's pull requests for $sha (HTTP $code); refusing to release on an unanswered check"
pr=$(jq -r --arg sha "$sha" --arg branch "$branch" '
  [.[]? | select(.merge_commit_sha == $sha and .merged_at != null
                 and .head.ref == $branch and .base.ref == "main")]
  | if length == 1 then "\(.[0].number) \(.[0].head.sha)" else empty end' "$work/pulls" 2>/dev/null) || pr=
[ -n "$pr" ] || die "no pull request from $branch was merged as $sha; tag only the commit the release pull request's merge put on main"
number=${pr%% *}
head=${pr#* }
matches "$number" '^[0-9]+$' || die "the forge named pull request '$number'"
matches "$head" '^[0-9a-f]{40}$' || die "the forge named head '$head' for pull request #$number"
ci_gate "$head" "the release pull request #$number's head"
echo "#$number $head"

#!/bin/sh
# release-publish.sh — publish (or converge) the forge release for a tag.
#
# Usage: scripts/release-publish.sh <tag> <commit-sha>   (from the repository root)
#
# Environment (all required):
#   FORGE_API_URL     the forge's API root, e.g. https://git.example.com/api/v1
#                     (release.yml passes the runner's GITHUB_API_URL)
#   FORGE_REPOSITORY  owner/repo
#   FORGE_TOKEN       the workflow's own token; it needs write access to the
#                     repository's releases and nothing else
#
# What it does, against the Gitea API (v1):
#   1. confirms the tag exists on the forge and names <commit-sha> — the
#      commit release.yml gated. A release is never attached to a tag the gate
#      did not see, and never created for a missing tag: Gitea's create-release
#      call CREATES an absent tag from the default branch, which would publish
#      a version pointing at whatever main happens to be;
#   2. creates the release, or, if one exists for the tag (a re-run), updates
#      it in place — name, body, prerelease — so re-running converges instead
#      of failing or duplicating. Nothing is ever deleted;
#   3. reads the release back and requires the stored body and prerelease
#      flag to be exactly what was sent.
#
# The body is the tag's CHANGELOG section (scripts/release-notes.sh). The
# release is a prerelease when the tag carries a SemVer 2.0.0 pre-release
# suffix (`-alpha` or `-rc.N`, release-versioning §1/§1a/§5), and a full release otherwise.
#
# NOT FOR GITHUB. Publishing a release on the public mirror is a publication
# that needs the owner's explicit, per-instance approval (release-versioning
# §5, devops §3); release.yml never calls this there, and this script refuses
# an api.github.com endpoint as a second, independent stop.
#
# The token never reaches a command line or the log: curl reads its
# Authorization header from a configuration on stdin.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 2 ] || die "usage: $0 <tag> <commit-sha>"
tag=$1
sha=$2
matches "$tag" "$VERSION_RE" || die "'$tag' is not vX.Y.Z[-pre]"
matches "$sha" '^[0-9a-f]{40}$' || die "'$sha' is not a 40-hex commit sha"

api=${FORGE_API_URL-}
repo=${FORGE_REPOSITORY-}
token=${FORGE_TOKEN-}
[ -n "$api" ] || die "FORGE_API_URL is unset"
[ -n "$repo" ] || die "FORGE_REPOSITORY is unset"
[ -n "$token" ] || die "FORGE_TOKEN is unset"

# The token is written into a curl configuration line, so a quote, backslash
# or newline in it could add directives of its own (a second line such as
# `url = "file:///…"` is a whole new request). The WHOLE value is checked
# against an explicit allowlist — newline included in what it refuses — with
# `case`, never with a line-oriented grep, which accepts a multi-line value
# as soon as any one line matches. Forge tokens are alphanumeric with `_`,
# `-` or `.`; anything else is refused, not escaped.
case $token in
  ''|*[!A-Za-z0-9_.-]*) die "FORGE_TOKEN has characters no forge token carries; refusing to use it" ;;
esac

# The API URL, checked as a whole and then by its host. A string prefix test
# is not a host test: `https://api.github.com:443`, `HTTPS://API.GITHUB.COM`,
# `http://api.github.com`, `https://x@api.github.com` and `https://api.github.com.`
# all reach GitHub. So: no whitespace, control or backslash anywhere; scheme
# http or https in any case; userinfo, port and trailing dots stripped; the
# host lowercased and limited to DNS characters; then any github.com host,
# or a subdomain of it, is refused.
case $api in
  *[!A-Za-z0-9._~:/?#@!\$\&\'\(\)*+,\;=%-]*) die "FORGE_API_URL contains characters a URL does not" ;;
esac
lower=$(printf '%s' "$api" | tr '[:upper:]' '[:lower:]')
case $lower in
  http://*)  rest=${lower#http://} ;;
  https://*) rest=${lower#https://} ;;
  *) die "FORGE_API_URL '$api' is not an http(s) URL" ;;
esac
authority=${rest%%[/?#]*}
host=${authority##*@}
host=${host%%:*}
while :; do
  case $host in *.) host=${host%.} ;; *) break ;; esac
done
case $host in
  ''|*[!a-z0-9.-]*) die "FORGE_API_URL '$api' has no host this script can verify; refusing to publish" ;;
esac
case $host in
  github.com|*.github.com)
    die "refusing to publish on GitHub ($host): that is the owner's explicit, per-instance decision (release-versioning §5)" ;;
esac
api=${api%/}
matches "$repo" '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' || die "FORGE_REPOSITORY '$repo' is not owner/repo"

for t in curl jq; do
  command -v "$t" >/dev/null 2>&1 || die "$t is required and was not found"
done

notes=$(sh "$here/release-notes.sh" "$tag" CHANGELOG.md) || die "no release notes for $tag"
case $tag in
  *-*) prerelease=true ;;
  *)   prerelease=false ;;
esac

work=$(mktemp -d "${TMPDIR:-/tmp}/release-publish.XXXXXX")
trap 'rm -rf "$work"' EXIT

# call METHOD PATH [BODY-FILE] -> prints the 3-digit HTTP status, 000 when no
# response arrived; the response body is left in $work/response.
call() {
  method=$1
  url=$api$2
  rm -f "$work/response"
  if [ $# -ge 3 ]; then
    set -- -H 'Content-Type: application/json' --data-binary "@$3"
  else
    set --
  fi
  code=$(printf 'header = "Authorization: token %s"\n' "$token" |
    curl --silent --show-error --config - \
      --connect-timeout 10 --max-time 60 \
      -X "$method" -H 'Accept: application/json' "$@" \
      -o "$work/response" -w '%{http_code}' "$url") || true
  case $code in
    [0-9][0-9][0-9]) printf '%s\n' "$code" ;;
    *) echo 000 ;;
  esac
}

show() { head -c 2000 "$work/response" 2>/dev/null >&2 || true; echo >&2; }

# 1. The tag exists and names the gated commit.
status=$(call GET "/repos/$repo/tags/$tag")
case $status in
  200) ;;
  404) die "tag $tag does not exist on the forge; refusing to let the release call create it" ;;
  *) show; die "reading tag $tag failed (HTTP $status)" ;;
esac
tagsha=$(jq -r '.commit.sha // empty' "$work/response")
[ "$tagsha" = "$sha" ] || die "tag $tag names commit '${tagsha:-<none>}' on the forge, but the gate ran on $sha; refusing to publish"

jq -n --arg tag "$tag" --arg body "$notes" --argjson pre "$prerelease" \
  '{tag_name: $tag, name: $tag, body: $body, draft: false, prerelease: $pre}' > "$work/payload"

# 2. Create, or converge an existing release.
status=$(call GET "/repos/$repo/releases/tags/$tag")
case $status in
  404)
    status=$(call POST "/repos/$repo/releases" "$work/payload")
    case $status in
      201) echo "$prog: created the $tag release" ;;
      *) show; die "creating the $tag release failed (HTTP $status)" ;;
    esac
    ;;
  200)
    id=$(jq -r '.id // empty' "$work/response")
    matches "$id" '^[0-9]+$' || die "the existing $tag release has no usable id"
    status=$(call PATCH "/repos/$repo/releases/$id" "$work/payload")
    case $status in
      200) echo "$prog: updated the existing $tag release (id $id)" ;;
      *) show; die "updating the $tag release failed (HTTP $status)" ;;
    esac
    ;;
  *) show; die "looking up the $tag release failed (HTTP $status)" ;;
esac

# 3. Read it back: what the forge stored is what was sent.
status=$(call GET "/repos/$repo/releases/tags/$tag")
[ "$status" = 200 ] || { show; die "reading back the $tag release failed (HTTP $status)"; }
jq -e --arg body "$notes" --argjson pre "$prerelease" \
  '.body == $body and .prerelease == $pre and .draft == false' "$work/response" >/dev/null ||
  die "the stored $tag release does not match what was sent (body, prerelease or draft differs)"
echo "$prog: $tag published (prerelease=$prerelease) with its CHANGELOG section as the body"

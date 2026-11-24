#!/bin/sh
# release-version-check.sh [--merged <commit>] <vX.Y.Z[-pre]> [<X.Y.Z[-pre]>]: refuse a version not strictly greater, by SemVer precedence, than VERSION and every v* tag.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

# SemVer 2.0.0's grammar: no leading zeros in numeric parts or numeric
# pre-release identifiers, non-empty dot-separated identifiers.
NUM='(0|[1-9][0-9]*)'
ID='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
SEMVER="$NUM\\.$NUM\\.$NUM(-$ID(\\.$ID)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?"

merged=
if [ "${1-}" = --merged ]; then
  [ $# -ge 2 ] || die "usage: $0 [--merged <commit>] <vX.Y.Z[-pre]> [<current VERSION>]"
  merged=$2
  shift 2
  git rev-parse --verify --quiet "$merged^{commit}" >/dev/null || die "--merged '$merged' does not name a commit"
fi
case $# in
  1 | 2) ;;
  *) die "usage: $0 [--merged <commit>] <vX.Y.Z[-pre]> [<current VERSION>]" ;;
esac
new=$1
matches "$new" "^v$SEMVER\$" || die "'$new' is not a v-prefixed SemVer 2.0.0 version"

if [ $# -eq 2 ]; then
  current=$2
else
  [ -f VERSION ] || die "VERSION not found (run from the repository root)"
  [ "$(wc -l < VERSION | tr -d ' ')" -le 1 ] || die "VERSION holds more than one line"
  current=$(cat VERSION)
fi
matches "$current" "^$SEMVER\$" || die "VERSION reads '$current', which is not an unprefixed SemVer version; refusing to order against it"

if [ -n "$merged" ]; then
  tags=$(git tag -l --merged "$merged" 'v*') || die "could not list the tags merged into $merged (git tag -l --merged)"
  scope="every v* tag merged into $merged"
else
  tags=$(git tag -l 'v*') || die "could not list tags (git tag -l 'v*')"
  scope="every existing v* tag"
fi
list="VERSION v$current"
for t in $tags; do
  matches "$t" "^v$SEMVER\$" || die "tag '$t' is not SemVer 2.0.0, so the new version cannot be ordered against it"
  list="$list$NL$t $t"
done

# Each line: "<label> <version>". Prints every entry the new version is not
# strictly greater than.
offenders=$(printf '%s\n' "$list" | NEW=$new awk '
function strip(v) { sub(/^v/, "", v); sub(/\+.*/, "", v); return v }
function isnum(s) { return s ~ /^[0-9]+$/ }
# Every comparison goes through cmpstr: split() yields strnums, which AWK
# compares as doubles ("1e10" vs "1e2", numerics past 2^53).
function cmpstr(a, b) {
  a = a ""; b = b ""
  return a < b ? -1 : (a > b ? 1 : 0)
}
# cmpnum compares two decimal strings without leading zeros, of any length.
function cmpnum(a, b) {
  if (length(a) != length(b)) return length(a) < length(b) ? -1 : 1
  return cmpstr(a, b)
}
function cmp(a, b,    pa, pb, ca, cb, na, nb, ia, ib, i, n, c) {
  a = strip(a); b = strip(b)
  pa = index(a, "-"); pb = index(b, "-")
  ca = pa ? substr(a, 1, pa - 1) : a
  cb = pb ? substr(b, 1, pb - 1) : b
  split(ca, na, "."); split(cb, nb, ".")
  for (i = 1; i <= 3; i++) if ((c = cmpnum(na[i], nb[i])) != 0) return c
  if (!pa && !pb) return 0
  if (!pa) return 1
  if (!pb) return -1
  n = split(substr(a, pa + 1), ia, "."); m = split(substr(b, pb + 1), ib, ".")
  for (i = 1; i <= n && i <= m; i++) {
    if (isnum(ia[i]) && isnum(ib[i])) { if ((c = cmpnum(ia[i], ib[i])) != 0) return c; continue }
    if (isnum(ia[i])) return -1
    if (isnum(ib[i])) return 1
    if ((c = cmpstr(ia[i], ib[i])) != 0) return c
  }
  return n < m ? -1 : (n > m ? 1 : 0)
}
NF == 2 && cmp(ENVIRON["NEW"], $2) <= 0 { print $1 " (" $2 ")" }
')

if [ -n "$offenders" ]; then
  echo "$prog: $new is not greater than:" >&2
  printf '%s\n' "$offenders" | sed 's/^/  /' >&2
  die "a release never lowers VERSION or goes below an existing tag (release-versioning §3); choose a higher version"
fi
echo "$prog: $new is greater than VERSION ($current) and $scope"

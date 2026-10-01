#!/bin/sh
# release-version-check.sh — refuse a release version that does not move forward.
#
# Usage: scripts/release-version-check.sh <vX.Y.Z[-pre]>   (from the repository root)
#
# `make release-alpha` runs this before it writes anything. release-versioning
# §3: a VERSION file is never lowered and a published tag is never superseded
# by a lower one — a backward version silently loses whatever the intervening
# releases fixed, and Go's MVS will happily keep selecting the higher one. So
# the new version must be STRICTLY greater, by SemVer 2.0.0 precedence (§11),
# than:
#   - the version VERSION holds now (unprefixed, release-versioning §2), and
#   - every existing `v*` tag in the repository.
#
# Precedence, per SemVer 2.0.0 §11: MAJOR, MINOR, PATCH compared numerically;
# a version with a pre-release is LOWER than the same version without one
# (v1.0.0-alpha < v1.0.0); pre-releases compare identifier by identifier —
# numeric identifiers numerically, numeric below alphanumeric, alphanumeric in
# ASCII order, and a shorter list below a longer one it prefixes. Build
# metadata (`+…`) does not take part.
#
# A `v*` tag that is not SemVer cannot be ordered, so it is refused rather than
# skipped: skipping it is exactly how a release could be cut below it.
set -eu
export LC_ALL=C

die() { echo "release-version-check: $*" >&2; exit 1; }

NL='
'
# The WHOLE value matches: `grep` alone is line-oriented.
matches() {
  case $1 in *"$NL"*) return 1 ;; esac
  printf '%s\n' "$1" | grep -Eq "$2"
}

# SemVer 2.0.0's grammar: no leading zeros in numeric parts or numeric
# pre-release identifiers, non-empty dot-separated identifiers.
NUM='(0|[1-9][0-9]*)'
ID='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
SEMVER="$NUM\\.$NUM\\.$NUM(-$ID(\\.$ID)*)?(\\+[0-9A-Za-z-]+(\\.[0-9A-Za-z-]+)*)?"

[ $# -eq 1 ] || die "usage: $0 <vX.Y.Z[-pre]>"
new=$1
matches "$new" "^v$SEMVER\$" || die "'$new' is not a v-prefixed SemVer 2.0.0 version"

[ -f VERSION ] || die "VERSION not found (run from the repository root)"
[ "$(wc -l < VERSION | tr -d ' ')" -le 1 ] || die "VERSION holds more than one line"
current=$(cat VERSION)
matches "$current" "^$SEMVER\$" || die "VERSION reads '$current', which is not an unprefixed SemVer version; refusing to order against it"

tags=$(git tag -l 'v*') || die "could not list tags (git tag -l 'v*')"
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
# cmpnum compares two decimal strings without leading zeros, of any length.
function cmpnum(a, b) {
  if (length(a) != length(b)) return length(a) < length(b) ? -1 : 1
  return a < b ? -1 : (a > b ? 1 : 0)
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
    if (ia[i] != ib[i]) return ia[i] < ib[i] ? -1 : 1
  }
  return n < m ? -1 : (n > m ? 1 : 0)
}
NF == 2 && cmp(ENVIRON["NEW"], $2) <= 0 { print $1 " (" $2 ")" }
')

if [ -n "$offenders" ]; then
  echo "release-version-check: $new is not greater than:" >&2
  printf '%s\n' "$offenders" | sed 's/^/  /' >&2
  die "a release never lowers VERSION or goes below an existing tag (release-versioning §3); choose a higher version"
fi
echo "release-version-check: $new is greater than VERSION ($current) and every existing v* tag"

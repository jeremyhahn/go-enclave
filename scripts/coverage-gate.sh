#!/bin/sh
# coverage-gate.sh — the one coverage floor, for unit and integration profiles.
#
# Usage: scripts/coverage-gate.sh <floor>
#        scripts/coverage-gate.sh <floor> <profile> [<import-path>...]
#        scripts/coverage-gate.sh merge <out> <profile>...
#
# With only a floor, checks that it is a number: `make coverage` does this
# BEFORE the suite spends minutes running.
#
# With a profile, fails unless every package in it, or each named import path,
# reaches the floor. The floor is compared on exact covered/total statements,
# never on a rounded percentage (89.96% is not 90%). A block is counted once,
# keyed by file and range, and the larger count wins should it appear twice.
# A block's package is its file's directory. A named import path with no block
# in the profile was never exercised, which is 0%, not "not applicable".
# Without names the total is gated too.
#
# merge concatenates cover profiles (the first one's mode line) into <out>.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

if [ "${1-}" = merge ]; then
  [ $# -ge 3 ] || die "usage: $0 merge <out> <profile>..."
  out=$2
  shift 2
  { head -n 1 "$1"; for f in "$@"; do tail -n +2 "$f"; done; } > "$out"
  exit 0
fi

[ $# -ge 1 ] || die "usage: $0 <floor> [<profile> [<import-path>...]]"
floor=$1
matches "$floor" '^[0-9]+(\.[0-9]+)?$' || die "the coverage floor must be a number"
[ $# -ge 2 ] || exit 0
profile=$2
shift 2
[ -f "$profile" ] || die "$profile not found"

awk -v floor="$floor" -v want="$*" '
BEGIN { nw = split(want, w, " ") }
NR == 1 && /^mode:/ { next }
NF == 3 {
  file = $1; sub(/:[^:]*$/, "", file)
  pkg = file; sub(/\/[^\/]*$/, "", pkg)
  if (!($1 in stmt)) { stmt[$1] = $2; cnt[$1] = $3; owner[$1] = pkg }
  else if ($3 > cnt[$1]) cnt[$1] = $3
}
function judge(name, tot, cov,    pct) {
  if (tot == 0) { print "FAIL: " name " has no coverage at all" > "/dev/stderr"; bad = 1; return }
  pct = 100 * cov / tot
  printf "%s coverage: %.2f%% (%d of %d statements, floor %s%%)\n", name, pct, cov, tot, floor | "sort"
  if (100 * cov < floor * tot) {
    failed[++nf] = sprintf("FAIL: %s coverage %.2f%% is below the %s%% floor", name, pct, floor)
    bad = 1
  }
}
END {
  for (k in stmt) {
    ptotal[owner[k]] += stmt[k]; all += stmt[k]
    if (cnt[k] > 0) { phit[owner[k]] += stmt[k]; allhit += stmt[k] }
  }
  if (nw > 0) {
    for (i = 1; i <= nw; i++) judge(w[i], ptotal[w[i]], phit[w[i]])
  } else {
    for (p in ptotal) { np++; judge(p, ptotal[p], phit[p]) }
    if (np == 0) { print "FAIL: no package in " ARGV[1] > "/dev/stderr"; exit 1 }
    judge("total", all, allhit)
  }
  close("sort")
  for (i = 1; i <= nf; i++) print failed[i] > "/dev/stderr"
  exit bad
}' "$profile"

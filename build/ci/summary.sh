#!/bin/sh
# summary.sh — the pass/fail summary a gate job ends with: one line per job,
# and a failure unless every job the run selected succeeded.
#
# Usage: sh build/ci/summary.sh <message> <full> <nightly> <tier>:<job>=<result>...
#
# <message> is the error printed when any job did not pass. <full> is `true`
# when this run selected the full tier and `false` when it did not; <nightly>
# is the same for the nightly tier (the schedule and workflow_dispatch). <tier>
# is `pr` (the job runs on every event), `full` (only when the full tier is
# selected) or `nightly` (only when the nightly tier is). A skipped job fails
# the gate like a failed one: a job that never ran proved nothing. The one
# exception is a `full` or `nightly` job skipped in a run that did not select
# its tier, because that job's `if:` was false by design. Anything else (an
# unknown tier, a <full> or <nightly> other than true or false) fails closed.
# The results arrive one per argument because Gitea does not implement
# join(needs.*.result) (it evaluates empty and reports success while jobs
# fail), so a workflow names every job it needs.
set -eu

[ $# -ge 4 ] || { echo "usage: $0 <message> <full> <nightly> <tier>:<job>=<result>..." >&2; exit 2; }
message=$1
full=$2
nightly=$3
shift 3
case $full in
  true|false) ;;
  *) echo "$0: <full> is '$full', want true or false" >&2; exit 2 ;;
esac
case $nightly in
  true|false) ;;
  *) echo "$0: <nightly> is '$nightly', want true or false" >&2; exit 2 ;;
esac

bad=0
for pair in "$@"; do
  tagged=${pair%%=*}
  result=${pair#*=}
  tier=${tagged%%:*}
  name=${tagged#*:}
  case $tier:$result in
    pr:success|full:success|nightly:success) printf 'OK   %s\n' "$name" ;;
    full:skipped|nightly:skipped)
      if { [ "$tier" = full ] && [ "$full" = false ]; } || { [ "$tier" = nightly ] && [ "$nightly" = false ]; }; then
        printf 'OK   %s (%s tier, not selected)\n' "$name" "$tier"
      else
        printf 'SKIP %s (did not run: see its job)\n' "$name"; bad=1
      fi ;;
    pr:skipped) printf 'SKIP %s (did not run: see its job)\n' "$name"; bad=1 ;;
    pr:*|full:*|nightly:*) printf 'FAIL %s (%s)\n' "$name" "$result"; bad=1 ;;
    *) printf 'FAIL %s (no pr:, full: or nightly: tier tag)\n' "$pair"; bad=1 ;;
  esac
done

if [ "$bad" -ne 0 ]; then
  echo "::error::$message"
fi
exit "$bad"

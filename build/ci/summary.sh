#!/bin/sh
# summary.sh — the pass/fail summary a gate job ends with: one line per job,
# and a failure unless every job's result is exactly `success`.
#
# Usage: sh build/ci/summary.sh <message> <job>=<result>...
#
# <message> is the error printed when any job did not pass. A skipped job fails
# the gate like a failed one: a job that never ran proved nothing. The results
# arrive one per argument because Gitea does not implement join(needs.*.result)
# (it evaluates empty and reports success while jobs fail), so a workflow names
# every job it needs.
set -eu

[ $# -ge 2 ] || { echo "usage: $0 <message> <job>=<result>..." >&2; exit 2; }
message=$1
shift

bad=0
for pair in "$@"; do
  name=${pair%%=*}
  result=${pair#*=}
  case $result in
    success) printf 'OK   %s\n' "$name" ;;
    skipped) printf 'SKIP %s (did not run: see its job)\n' "$name"; bad=1 ;;
    *)       printf 'FAIL %s (%s)\n' "$name" "$result"; bad=1 ;;
  esac
done

if [ "$bad" -ne 0 ]; then
  echo "::error::$message"
fi
exit "$bad"

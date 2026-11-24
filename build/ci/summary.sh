#!/bin/sh
# summary.sh <message> <full> <nightly> <tier>:<job>=<result>...: fails unless every selected job succeeded; unknown input fails closed.
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

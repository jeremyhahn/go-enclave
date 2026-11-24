#!/bin/sh
# scan.sh <name> <finding> <command> [arg...]: run a scanner and say whether it found something or was killed by a signal.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -ge 3 ] || die "usage: $0 <name> <finding> <command> [arg...]"
name=$1
finding=$2
shift 2

rc=0
for dir in ${SCAN_MODULES:-.}; do
  (cd -- "$dir" && "$@") || rc=$?
  [ "$rc" -eq 0 ] || break
done
if [ "$rc" -gt 128 ]; then
  echo "$name was KILLED by signal $((rc - 128)) - this is NOT $finding. Memory pressure; re-run when the host is quieter and confirm with an uncapped run."
fi
exit "$rc"

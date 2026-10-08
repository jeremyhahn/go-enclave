#!/bin/sh
# scan.sh — run a scanner and say whether it FOUND something or was KILLED.
#
# Usage: [SCAN_MODULES="dir..."] scripts/scan.sh <name> <finding> <command> [arg...]
#
# Runs the command in the repository root, or in each directory of SCAN_MODULES
# (stopping at the first failure). An exit above 128 means killed by a signal
# (e.g. OOM), not findings: a shell reports a signal death as 128+N, which a job
# summary cannot tell from a real finding. The run fails either way; this only
# says which. <finding> names what a real failure would be ("a security finding").
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

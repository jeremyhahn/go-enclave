#!/bin/sh
# features.sh — the features a change touches, one per line.
#
# Usage: scripts/features.sh <base> <tip>   (from the repository root)
#
# The factory's FEATURES_CMD (local-software-factory §7). A feature is a
# directory docs/<feature>/; it is touched when a file under it differs between
# <base> and <tip>. The Makefile maps each feature to `test-<pkg>` and
# `integration-test-<feature>`. Prints nothing when no feature is touched.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 2 ] || die "usage: $0 <base> <tip>"
for ref in "$1" "$2"; do
  case $ref in -*) die "'$ref' is not a revision" ;; esac
  git rev-parse --verify --quiet --end-of-options "$ref^{commit}" >/dev/null || die "'$ref' does not name a commit"
done

git -c core.quotePath=false diff --name-only --no-renames "$1" "$2" -- docs |
  awk -F/ 'NF > 2 && $1 == "docs" { print $2 }' |
  sort -u

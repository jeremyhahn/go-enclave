#!/bin/sh
# git diff --name-only <range> | optee-selected.sh <pins-diff>: prints true when the change reaches the OP-TEE harness job, else false.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 1 ] || die "usage: $0 <pins-diff> < changed-paths"
[ -f "$1" ] || die "pins diff $1 is missing"

paths='^(backends/armtrustzone/|build/docker/devcontainer/|Makefile$|\.github/workflows/ci\.yml$|test/integration/enclave/main_optee_test\.go$|scripts/(optee-fixture|optee-selected|in-toolchain-image|devcontainer|lib|tool|install-tools)\.sh$)'
pins='^[-+](TRUSTED_FIRMWARE_[A-Z_]*|OPTEE_FIXTURE_IMAGE)='

if grep -qE "$paths" || grep -qE "$pins" "$1"; then
  echo true
else
  echo false
fi

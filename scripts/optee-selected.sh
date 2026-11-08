#!/bin/sh
# optee-selected.sh — does a change reach the OP-TEE harness?
#
# Usage: git diff --name-only <range> | scripts/optee-selected.sh <pins-diff>
#
# Reads the changed paths, one per line, on stdin; <pins-diff> is a file
# holding the diff of scripts/tool-pins.sh over the same range. Prints true
# when the change reaches what ci.yml's integration-test-arm-trustzone job
# builds or runs, else false. A missing <pins-diff> is an error: ci.yml
# selects the job whenever this script fails.
#
# Selected paths:
#   backends/armtrustzone/             the backend and its optee-tagged test
#   scripts/optee-fixture.sh           the fixture the harness runs in
#   test/integration/enclave/main_optee_test.go  the root's optee harness
#   Makefile                           the recipe's cross-compilation, fixture
#                                      container and checkout copy
#   scripts/in-toolchain-image.sh      the recipe's toolchain container
#   scripts/devcontainer.sh            docker-build and toolchain-image
#   scripts/lib.sh                     sourced by each script above
#   scripts/tool.sh, scripts/install-tools.sh  copied into the toolchain
#                                      image (devcontainer.sh inputs)
#   build/docker/devcontainer/         the images' Dockerfile and compose file
#   scripts/optee-selected.sh          this selector
# and, in the pins diff, a changed TRUSTED_FIRMWARE_* or OPTEE_FIXTURE_IMAGE
# line: the release the fixture boots and the image it runs in.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -eq 1 ] || die "usage: $0 <pins-diff> < changed-paths"
[ -f "$1" ] || die "pins diff $1 is missing"

paths='^(backends/armtrustzone/|build/docker/devcontainer/|Makefile$|test/integration/enclave/main_optee_test\.go$|scripts/(optee-fixture|optee-selected|in-toolchain-image|devcontainer|lib|tool|install-tools)\.sh$)'
pins='^[-+](TRUSTED_FIRMWARE_[A-Z_]*|OPTEE_FIXTURE_IMAGE)='

if grep -qE "$paths" || grep -qE "$pins" "$1"; then
  echo true
else
  echo false
fi

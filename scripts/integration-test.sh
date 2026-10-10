#!/bin/sh
# integration-test.sh — one package's integration suite, in the devcontainer.
#
# Usage: scripts/integration-test.sh <package> <coverpkg> [docker-run-flag...]
#
# The body of `make integration-test-<package>` (and -fips, which adds -e flags
# after <coverpkg>). The suite (test/integration/<package>/) runs in the
# devcontainer, never on the host. The image bakes the source because on CI
# runners compose talks to the host daemon, where bind-mount paths do not exist.
# Each run uses a unique compose project, torn down on every exit. The package
# is named exactly (no /...) so a wrong build tag errors instead of passing
# vacuously. Every precondition fails rather than skips.
#
# The suite runs on an image that scripts/integration-image.sh built once and
# trivy-scanned (CRITICAL,HIGH, fixable only — devops §8): this script neither
# builds nor scans. Unless GO_ENCLAVE_IT_IMAGE is set, which that script does,
# this one runs through it, so a single suite is built and scanned the same way
# and `make ci-integration` shares one scanned image across userns, default and
# FIPS.
#
# <coverpkg> is the comma-separated import paths the suite's coverage floor
# applies to, each package on its own.
#
# Environment (exported by the Makefile): DEVCONTAINER_COMPOSE,
# DEVCONTAINER_SERVICE, INTEGRATION_TESTFLAGS, COVERAGE_THRESHOLD, TRIVY_VERSION
# and optionally GO_ENCLAVE_IT_PROFILE_OUT.
set -eu
# shellcheck source=lib.sh
. "${0%/*}/lib.sh"

[ $# -ge 2 ] || die "usage: $0 <package> <coverpkg> [docker-run-flag...]"
pkg=$1
coverpkg=$2
shift 2
[ -n "$coverpkg" ] || die "no coverage package for $pkg: every integration suite names the package its coverage floor applies to"
compose=${DEVCONTAINER_COMPOSE:?DEVCONTAINER_COMPOSE is required}
service=${DEVCONTAINER_SERVICE:?DEVCONTAINER_SERVICE is required}

[ -d "test/integration/$pkg" ] || die "test/integration/$pkg does not exist. Refusing to report a suite that did not run as passed."
ls "test/integration/$pkg"/*_test.go >/dev/null 2>&1 || die "test/integration/$pkg holds no _test.go files; refusing to pass with nothing to run."
[ -f "$compose" ] || die "$compose not found. Integration tests run in the project devcontainer, never on the host (integration-testing §4)."
{ command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; } || die "'docker compose' (Compose v2) is required to run the integration suite in the devcontainer."
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || die "the Docker daemon is not reachable (docker version cannot read the server). The integration suite runs in the devcontainer and cannot run without it."

if [ -z "${GO_ENCLAVE_IT_IMAGE-}" ]; then
  exec sh "$here/integration-image.sh" sh "$here/integration-test.sh" "$pkg" "$coverpkg" "$@"
fi
require_scanned_image

project="go-enclave-it-$pkg-$(date +%s)-$$-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
echo "compose project: $project"

# The image is not this project's to remove (it is named by GO_ENCLAVE_IT_IMAGE,
# and compose's --rmi local leaves a named image alone); integration-image.sh
# removes it after the last suite.
cleanup() {
  rc=$?
  if ! docker compose -f "$compose" -p "$project" down --volumes --remove-orphans >/dev/null 2>&1; then
    echo "ERROR: teardown of compose project $project failed; remove it with: docker compose -f '$compose' -p '$project' down --volumes --remove-orphans" >&2
    [ "$rc" -ne 0 ] || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker compose -f "$compose" -p "$project" run --rm --pull never \
  -e GO_ENCLAVE_IT_TESTFLAGS="${INTEGRATION_TESTFLAGS:?INTEGRATION_TESTFLAGS is required}" \
  -e GO_ENCLAVE_IT_COVERAGE_FLOOR="${COVERAGE_THRESHOLD:?COVERAGE_THRESHOLD is required}" \
  -e GO_ENCLAVE_IT_COVERPKG="$coverpkg" \
  -e GO_ENCLAVE_IT_PROFILE_OUT="${GO_ENCLAVE_IT_PROFILE_OUT-}" \
  "$@" "$service" sh build/docker/devcontainer/run-integration-tests.sh "$pkg"

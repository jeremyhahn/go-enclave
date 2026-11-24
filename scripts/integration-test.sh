#!/bin/sh
# integration-test.sh <package> <coverpkg> [docker-run-flag...]: one package's integration suite in the devcontainer, on an image scripts/integration-image.sh built once and
# trivy-scanned (CRITICAL,HIGH, fixable only — devops §8): this script neither
# builds nor scans it.
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
# and compose's --rmi local leaves a named image alone); it is named by
# content and kept for the next run of the same tree (integration-image.sh).
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

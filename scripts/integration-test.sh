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
# <coverpkg> is the import path the package's coverage floor applies to.
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

trivy=$(sh "$here/tool.sh" trivy "${TRIVY_VERSION:?TRIVY_VERSION is required}")
project="go-enclave-it-$pkg-$(date +%s)-$$-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
echo "compose project: $project"

cleanup() {
  rc=$?
  if ! docker compose -f "$compose" -p "$project" down --volumes --remove-orphans --rmi local >/dev/null 2>&1; then
    echo "ERROR: teardown of compose project $project failed; remove it with: docker compose -f '$compose' -p '$project' down --volumes --remove-orphans --rmi local" >&2
    [ "$rc" -ne 0 ] || rc=1
  fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

docker compose -f "$compose" -p "$project" build "$service"
echo "trivy image $project-$service (CRITICAL,HIGH, fixable only — devops §8)"
"$trivy" image --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 \
  --ignorefile .trivyignore --skip-version-check --format table "$project-$service"
docker compose -f "$compose" -p "$project" run --rm \
  -e GO_ENCLAVE_IT_TESTFLAGS="${INTEGRATION_TESTFLAGS:?INTEGRATION_TESTFLAGS is required}" \
  -e GO_ENCLAVE_IT_COVERAGE_FLOOR="${COVERAGE_THRESHOLD:?COVERAGE_THRESHOLD is required}" \
  -e GO_ENCLAVE_IT_COVERPKG="$coverpkg" \
  -e GO_ENCLAVE_IT_PROFILE_OUT="${GO_ENCLAVE_IT_PROFILE_OUT-}" \
  "$@" "$service" sh build/docker/devcontainer/run-integration-tests.sh "$pkg"
